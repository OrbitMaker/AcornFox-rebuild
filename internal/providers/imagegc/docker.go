package imagegc

// DockerInventory is an Agent-side, task-scoped adapter. It intentionally
// talks to Docker only through argv-based Runner calls and its deletion method
// only addresses a verified, labelled image digest. The control plane can use
// Provider with this adapter but must not run it itself.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/open-card/open-card/internal/domain"
)

var dockerSafeName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*$`)

type DockerRunner interface {
	Run(context.Context, string, []string, io.Writer, io.Writer) error
}

type dockerExecRunner struct{}

func (dockerExecRunner) Run(ctx context.Context, command string, args []string, stdout, stderr io.Writer) error {
	cmd := exec.CommandContext(ctx, command, args...)
	cmd.Stdout, cmd.Stderr = stdout, stderr
	return cmd.Run()
}

// ReleaseBuildSnapshot is the persistence-side read-only contract. A Store
// adapter must map unknown lifecycle state to an error; it must not classify
// unknown data as safely collectible.
type ReleaseBuildSnapshot interface {
	ListGCReleases(context.Context) ([]ReleaseRecord, error)
	ListGCBuilds(context.Context) ([]BuildRecord, error)
}

type DockerConfig struct {
	Command    string
	TaskPrefix string
	DiskPath   string
	Timeout    time.Duration
	Runner     DockerRunner
	Snapshot   ReleaseBuildSnapshot
}

type DockerInventory struct{ config DockerConfig }

func NewDockerInventory(config DockerConfig) (*DockerInventory, error) {
	if strings.TrimSpace(config.Command) == "" {
		config.Command = "docker"
	}
	if !dockerSafeName.MatchString(strings.TrimSpace(config.TaskPrefix)) {
		return nil, errors.New("image GC task prefix must be a safe non-empty name")
	}
	config.TaskPrefix = strings.TrimSpace(config.TaskPrefix)
	if config.DiskPath == "" {
		config.DiskPath = "/var/lib/docker"
	}
	if !filepath.IsAbs(config.DiskPath) || strings.Contains(filepath.Clean(config.DiskPath), "..") {
		return nil, errors.New("image GC disk path must be an absolute clean path")
	}
	if config.Timeout == 0 {
		config.Timeout = 2 * time.Minute
	}
	if config.Timeout <= 0 || config.Snapshot == nil {
		return nil, errors.New("image GC timeout and release/build snapshot are required")
	}
	if config.Runner == nil {
		config.Runner = dockerExecRunner{}
	}
	return &DockerInventory{config: config}, nil
}

func (d *DockerInventory) ListResources(ctx context.Context) ([]Resource, error) {
	authorized, err := d.snapshotImages(ctx)
	if err != nil {
		return nil, err
	}
	var imageLines []dockerImageList
	if err := d.jsonLines(ctx, "image-list", []string{"image", "ls", "--filter", "label=open-card.managed=true", "--filter", "label=open-card.task-prefix=" + d.config.TaskPrefix, "--digests", "--no-trunc", "--format", "{{json .}}"}, &imageLines); err != nil {
		return nil, err
	}
	resources := make([]Resource, 0, len(imageLines))
	seen := make(map[string]struct{}, len(imageLines))
	for _, line := range imageLines {
		repository, digest, ok := dockerImageReference(line.Repository, line.Digest)
		if !ok {
			continue // dangling images cannot prove immutable digest ownership.
		}
		image, err := domain.ParseImageDigest(repository, digest)
		if err != nil {
			return nil, fmt.Errorf("Docker returned invalid image digest: %w", err)
		}
		key := imageKey(image)
		if _, exists := seen[key]; exists {
			continue
		}
		facts, err := d.inspectImage(ctx, repository+"@"+digest)
		if err != nil {
			return nil, err
		}
		if !d.ownedImage(facts) {
			return nil, errors.New("Docker image list ownership changed during GC inventory")
		}
		seen[key] = struct{}{}
		resources = append(resources, Resource{Kind: ResourceImage, Name: facts.ID, Image: image, SizeBytes: facts.Size, CreatedAt: parseDockerTime(facts.Created)})
	}
	// Build and registry images need not carry provider labels in their immutable
	// config.  Their exact repository+digest can still be safely inventoried
	// when that identity comes from the durable Release/Build snapshot.
	for key, image := range authorized {
		if _, exists := seen[key]; exists {
			continue
		}
		facts, inspectErr := d.inspectAuthorizedImage(ctx, image)
		if inspectErr != nil {
			continue // persisted OCI content may not currently be loaded in Docker.
		}
		if !factsContainImage(facts, image) {
			return nil, errors.New("Docker image identity changed during GC inventory")
		}
		seen[key] = struct{}{}
		resources = append(resources, Resource{Kind: ResourceImage, Name: facts.ID, Image: image, SizeBytes: facts.Size, CreatedAt: parseDockerTime(facts.Created)})
	}
	var volumes []dockerVolumeList
	if err := d.jsonLines(ctx, "volume-list", []string{"volume", "ls", "--filter", "label=open-card.managed=true", "--filter", "label=open-card.task-prefix=" + d.config.TaskPrefix, "--format", "{{json .}}"}, &volumes); err != nil {
		return nil, err
	}
	for _, volume := range volumes {
		if dockerSafeName.MatchString(volume.Name) {
			resources = append(resources, Resource{Kind: ResourceVolume, Name: volume.Name})
		}
	}
	return resources, nil
}

func (d *DockerInventory) ListReleases(ctx context.Context) ([]ReleaseRecord, error) {
	return d.config.Snapshot.ListGCReleases(ctx)
}
func (d *DockerInventory) ListBuilds(ctx context.Context) ([]BuildRecord, error) {
	return d.config.Snapshot.ListGCBuilds(ctx)
}

func (d *DockerInventory) ListRuntimeUse(ctx context.Context) ([]RuntimeUse, error) {
	authorized, err := d.snapshotImages(ctx)
	if err != nil {
		return nil, err
	}
	var containers []dockerContainerList
	if err := d.jsonLines(ctx, "container-list", []string{"ps", "--filter", "status=running", "--filter", "label=open-card.managed=true", "--filter", "label=open-card.task-prefix=" + d.config.TaskPrefix, "--no-trunc", "--format", "{{json .}}"}, &containers); err != nil {
		return nil, err
	}
	uses := make([]RuntimeUse, 0)
	seen := make(map[string]struct{})
	for _, container := range containers {
		if strings.TrimSpace(container.ID) == "" {
			return nil, errors.New("Docker returned a runtime container without an ID")
		}
		var inspect dockerContainerInspect
		if err := d.jsonValue(ctx, "container-inspect", []string{"container", "inspect", "--format", "{{json .}}", container.ID}, &inspect); err != nil {
			return nil, err
		}
		if inspect.Config.Labels["open-card.managed"] != "true" || inspect.Config.Labels["open-card.task-prefix"] != d.config.TaskPrefix || strings.TrimSpace(inspect.Image) == "" {
			return nil, errors.New("Docker runtime container ownership is invalid")
		}
		facts, err := d.inspectImage(ctx, inspect.Image)
		if err != nil {
			return nil, err
		}
		matched := make(map[string]domain.ImageDigest)
		for _, reference := range facts.RepoDigests {
			repository, digest, ok := splitDigestReference(reference)
			if !ok {
				return nil, errors.New("Docker returned malformed runtime image digest")
			}
			image, err := domain.ParseImageDigest(repository, digest)
			if err != nil {
				return nil, err
			}
			key := imageKey(image)
			if authorizedImage, ok := authorized[key]; ok {
				matched[key] = authorizedImage
			}
		}
		// BuildKit OCI loads can be intentionally untagged; Docker then exposes
		// only the immutable image ID. Protect every durable snapshot reference
		// with that digest rather than guessing one repository.
		for key, image := range authorized {
			if image.Digest == facts.ID {
				matched[key] = image
			}
		}
		if len(matched) == 0 {
			return nil, errors.New("running task image is absent from the durable Release/Build snapshot")
		}
		for key, image := range matched {
			if _, exists := seen[key]; !exists {
				seen[key] = struct{}{}
				uses = append(uses, RuntimeUse{Image: image, InUse: true, DeploymentID: inspect.Config.Labels["open-card.deployment-id"]})
			}
		}
	}
	return uses, nil
}

func (d *DockerInventory) DiskUsage(_ context.Context) (DiskUsage, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(d.config.DiskPath, &stat); err != nil {
		return DiskUsage{}, fmt.Errorf("stat image GC disk path: %w", err)
	}
	total := int64(stat.Blocks) * int64(stat.Bsize)
	available := int64(stat.Bavail) * int64(stat.Bsize)
	if total <= 0 || available < 0 || available > total {
		return DiskUsage{}, errors.New("image GC disk usage is invalid")
	}
	return DiskUsage{TotalBytes: total, UsedBytes: total - available, AvailableBytes: available, ObservedAt: time.Now().UTC()}, nil
}

// DeleteImage rechecks ownership immediately before Docker removal. It does
// not force removal: Docker itself therefore blocks any reference that escaped
// the preceding runtime observation instead of untagging it under a process.
func (d *DockerInventory) DeleteImage(ctx context.Context, image domain.ImageDigest) error {
	if err := image.Validate(); err != nil {
		return err
	}
	reference := image.Repository + "@" + image.Digest
	facts, err := d.inspectAuthorizedImage(ctx, image)
	if err != nil {
		return err
	}
	authorized, snapshotErr := d.snapshotImages(ctx)
	if snapshotErr != nil {
		return snapshotErr
	}
	if !factsContainImage(facts, image) || (!d.ownedImage(facts) && authorized[imageKey(image)] == (domain.ImageDigest{})) {
		return errors.New("refusing to delete an image outside the task namespace")
	}
	deleteReference := reference
	if facts.ID == image.Digest {
		foundRepositoryDigest := false
		for _, value := range facts.RepoDigests {
			foundRepositoryDigest = foundRepositoryDigest || value == reference
		}
		if !foundRepositoryDigest {
			deleteReference = image.Digest
		}
	}
	return d.run(ctx, "image-remove", []string{"image", "rm", deleteReference})
}

func (d *DockerInventory) inspectAuthorizedImage(ctx context.Context, image domain.ImageDigest) (dockerImageInspect, error) {
	if facts, err := d.inspectImage(ctx, image.Repository+"@"+image.Digest); err == nil {
		return facts, nil
	}
	return d.inspectImage(ctx, image.Digest)
}

func (d *DockerInventory) snapshotImages(ctx context.Context) (map[string]domain.ImageDigest, error) {
	releases, err := d.config.Snapshot.ListGCReleases(ctx)
	if err != nil {
		return nil, err
	}
	builds, err := d.config.Snapshot.ListGCBuilds(ctx)
	if err != nil {
		return nil, err
	}
	images := make(map[string]domain.ImageDigest)
	for _, release := range releases {
		if err := release.validate(); err != nil {
			return nil, err
		}
		for _, image := range release.Images {
			images[imageKey(image)] = image
		}
	}
	for _, build := range builds {
		if err := build.validate(); err != nil {
			return nil, err
		}
		for _, image := range build.Images {
			images[imageKey(image)] = image
		}
	}
	return images, nil
}

func factsContainImage(facts dockerImageInspect, image domain.ImageDigest) bool {
	if facts.ID == image.Digest {
		return true
	}
	wanted := image.Repository + "@" + image.Digest
	for _, reference := range facts.RepoDigests {
		if reference == wanted {
			return true
		}
	}
	return false
}

type dockerImageList struct {
	Repository string `json:"Repository"`
	Digest     string `json:"Digest"`
}
type dockerVolumeList struct {
	Name string `json:"Name"`
}
type dockerContainerList struct {
	ID string `json:"ID"`
}
type dockerImageInspect struct {
	ID          string   `json:"Id"`
	Created     string   `json:"Created"`
	Size        int64    `json:"Size"`
	RepoDigests []string `json:"RepoDigests"`
	Config      struct {
		Labels map[string]string `json:"Labels"`
	} `json:"Config"`
}
type dockerContainerInspect struct {
	Image  string `json:"Image"`
	Config struct {
		Labels map[string]string `json:"Labels"`
	} `json:"Config"`
}

func (d *DockerInventory) inspectImage(ctx context.Context, reference string) (dockerImageInspect, error) {
	var facts dockerImageInspect
	if err := d.jsonValue(ctx, "image-inspect", []string{"image", "inspect", "--format", "{{json .}}", reference}, &facts); err != nil {
		return dockerImageInspect{}, err
	}
	if strings.TrimSpace(facts.ID) == "" || facts.Size < 0 {
		return dockerImageInspect{}, errors.New("Docker returned invalid image facts")
	}
	return facts, nil
}

func (d *DockerInventory) ownedImage(facts dockerImageInspect) bool {
	return facts.Config.Labels != nil && facts.Config.Labels["open-card.managed"] == "true" && facts.Config.Labels["open-card.task-prefix"] == d.config.TaskPrefix
}

func (d *DockerInventory) jsonLines(ctx context.Context, action string, args []string, destination any) error {
	var stdout bytes.Buffer
	if err := d.runTo(ctx, action, args, &stdout); err != nil {
		return err
	}
	lines := strings.Split(strings.TrimSpace(stdout.String()), "\n")
	if strings.TrimSpace(stdout.String()) == "" {
		return nil
	}
	values := make([]json.RawMessage, 0, len(lines))
	for _, line := range lines {
		if !json.Valid([]byte(line)) {
			return errors.New("Docker returned malformed JSON list")
		}
		values = append(values, append(json.RawMessage(nil), line...))
	}
	encoded, _ := json.Marshal(values)
	if err := json.Unmarshal(encoded, destination); err != nil {
		return errors.New("Docker JSON list did not match expected facts")
	}
	return nil
}

func (d *DockerInventory) jsonValue(ctx context.Context, action string, args []string, destination any) error {
	var stdout bytes.Buffer
	if err := d.runTo(ctx, action, args, &stdout); err != nil {
		return err
	}
	if err := json.Unmarshal(stdout.Bytes(), destination); err != nil {
		return errors.New("Docker JSON facts did not match expected shape")
	}
	return nil
}

func (d *DockerInventory) run(ctx context.Context, action string, args []string) error {
	return d.runTo(ctx, action, args, io.Discard)
}
func (d *DockerInventory) runTo(ctx context.Context, action string, args []string, stdout io.Writer) error {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, d.config.Timeout)
	defer cancel()
	var stderr bytes.Buffer
	if err := d.config.Runner.Run(ctx, d.config.Command, append([]string(nil), args...), stdout, &stderr); err != nil {
		return fmt.Errorf("Docker %s failed", action)
	}
	return nil
}

func dockerImageReference(repository, digest string) (string, string, bool) {
	if repository == "" || repository == "<none>" || !strings.HasPrefix(digest, "sha256:") {
		return "", "", false
	}
	return repository, digest, true
}
func splitDigestReference(reference string) (string, string, bool) {
	index := strings.LastIndex(reference, "@")
	if index <= 0 || index == len(reference)-1 {
		return "", "", false
	}
	return reference[:index], reference[index+1:], true
}
func parseDockerTime(value string) time.Time {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}
	}
	return parsed.UTC()
}

var _ Inventory = (*DockerInventory)(nil)
var _ ImageDeleter = (*DockerInventory)(nil)
