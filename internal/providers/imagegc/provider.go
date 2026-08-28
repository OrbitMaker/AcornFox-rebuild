// Package imagegc plans and executes safe local image garbage collection.
//
// The package is deliberately independent from a Docker client and from the
// ImageStore contract.  The control plane supplies a read-only inventory and
// an image-only deleter.  This keeps retention policy testable without giving
// a planner permission to delete volumes or arbitrary host paths.
package imagegc

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strings"
	"time"

	"github.com/open-card/open-card/internal/domain"
)

const (
	DefaultKeepSuccessfulReleases = 3
	DefaultSoftWatermarkPercent   = 80
	DefaultHardWatermarkPercent   = 90
)

var (
	ErrInvalidConfig    = errors.New("image garbage collection configuration is invalid")
	ErrInvalidInventory = errors.New("image garbage collection inventory is invalid")
)

// ResourceKind identifies an inventory object.  Only ResourceImage can ever
// become a candidate.  ResourceVolume is intentionally represented here so a
// Docker inventory adapter can prove that volumes were observed and skipped;
// ImageDeleter has no volume operation by design.
type ResourceKind string

const (
	ResourceImage  ResourceKind = "image"
	ResourceVolume ResourceKind = "volume"
)

// Resource is one immutable inventory item.  Image must be populated only for
// ResourceImage.  BuildID is optional and lets failed/in-progress build
// references be associated even when the BuildRecord carries no image list.
type Resource struct {
	Kind      ResourceKind       `json:"kind"`
	Name      string             `json:"name,omitempty"`
	Image     domain.ImageDigest `json:"image,omitempty"`
	SizeBytes int64              `json:"size_bytes"`
	CreatedAt time.Time          `json:"created_at"`
	BuildID   string             `json:"build_id,omitempty"`
}

func (r Resource) validate() error {
	if r.SizeBytes < 0 {
		return fmt.Errorf("%w: resource %q has negative size", ErrInvalidInventory, r.Name)
	}
	switch r.Kind {
	case ResourceImage:
		if err := r.Image.Validate(); err != nil {
			return fmt.Errorf("%w: image resource %q has invalid digest: %v", ErrInvalidInventory, r.Name, err)
		}
	case ResourceVolume:
		if strings.TrimSpace(r.Name) == "" {
			return fmt.Errorf("%w: volume resource name is required", ErrInvalidInventory)
		}
		if r.Image != (domain.ImageDigest{}) {
			return fmt.Errorf("%w: volume %q carries an image reference", ErrInvalidInventory, r.Name)
		}
	default:
		return fmt.Errorf("%w: resource %q has unsupported kind %q", ErrInvalidInventory, r.Name, r.Kind)
	}
	return nil
}

// ReleaseStatus is intentionally local to this package.  Adapters map their
// persistence states to these explicit meanings before invoking the planner.
// Unknown states are rejected instead of being silently treated as deletable.
type ReleaseStatus string

const (
	ReleaseSucceeded  ReleaseStatus = "succeeded"
	ReleaseCurrent    ReleaseStatus = "current"
	ReleaseInProgress ReleaseStatus = "in_progress"
	ReleaseRollback   ReleaseStatus = "rollback"
	ReleaseFailed     ReleaseStatus = "failed"
	ReleaseReady      ReleaseStatus = "ready"
	ReleaseServing    ReleaseStatus = "serving"
	ReleaseSuperseded ReleaseStatus = "superseded"
)

// ReleaseRecord contains only image references and lifecycle facts needed for
// retention.  Successful is an explicit adapter override for stores whose
// status names differ; it does not make an unknown Status valid.
type ReleaseRecord struct {
	ID         string               `json:"id"`
	Status     ReleaseStatus        `json:"status"`
	Successful bool                 `json:"successful,omitempty"`
	Current    bool                 `json:"current,omitempty"`
	InProgress bool                 `json:"in_progress,omitempty"`
	Rollback   bool                 `json:"rollback,omitempty"`
	CreatedAt  time.Time            `json:"created_at"`
	Images     []domain.ImageDigest `json:"images"`
}

func (r ReleaseRecord) validate() error {
	if strings.TrimSpace(r.ID) == "" {
		return fmt.Errorf("%w: release id is required", ErrInvalidInventory)
	}
	switch r.Status {
	case ReleaseSucceeded, ReleaseCurrent, ReleaseInProgress, ReleaseRollback,
		ReleaseFailed, ReleaseReady, ReleaseServing, ReleaseSuperseded:
	case "":
		if !r.Successful && !r.Current && !r.InProgress && !r.Rollback {
			return fmt.Errorf("%w: release %q has no lifecycle status", ErrInvalidInventory, r.ID)
		}
	default:
		return fmt.Errorf("%w: release %q has unsupported status %q", ErrInvalidInventory, r.ID, r.Status)
	}
	for _, image := range r.Images {
		if err := image.Validate(); err != nil {
			return fmt.Errorf("%w: release %q image is invalid: %v", ErrInvalidInventory, r.ID, err)
		}
	}
	return nil
}

func (r ReleaseRecord) isSuccessful() bool {
	return r.Successful || r.Status == ReleaseSucceeded || r.Status == ReleaseCurrent || r.Status == ReleaseReady || r.Status == ReleaseServing
}

func (r ReleaseRecord) isCurrent() bool {
	return r.Current || r.Status == ReleaseCurrent
}

func (r ReleaseRecord) isInProgress() bool {
	return r.InProgress || r.Status == ReleaseInProgress
}

func (r ReleaseRecord) isRollback() bool {
	return r.Rollback || r.Status == ReleaseRollback
}

// BuildStatus describes image provenance relevant to collection.
type BuildStatus string

const (
	BuildSucceeded  BuildStatus = "succeeded"
	BuildPending    BuildStatus = "pending"
	BuildRunning    BuildStatus = "running"
	BuildInProgress BuildStatus = "in_progress"
	BuildFailed     BuildStatus = "failed"
	BuildCancelled  BuildStatus = "cancelled"
)

type BuildRecord struct {
	ID        string               `json:"id"`
	Status    BuildStatus          `json:"status"`
	CreatedAt time.Time            `json:"created_at"`
	Images    []domain.ImageDigest `json:"images"`
}

func (b BuildRecord) validate() error {
	if strings.TrimSpace(b.ID) == "" {
		return fmt.Errorf("%w: build id is required", ErrInvalidInventory)
	}
	switch b.Status {
	case BuildSucceeded, BuildPending, BuildRunning, BuildInProgress, BuildFailed, BuildCancelled:
	default:
		return fmt.Errorf("%w: build %q has unsupported status %q", ErrInvalidInventory, b.ID, b.Status)
	}
	for _, image := range b.Images {
		if err := image.Validate(); err != nil {
			return fmt.Errorf("%w: build %q image is invalid: %v", ErrInvalidInventory, b.ID, err)
		}
	}
	return nil
}

// RuntimeUse is a point-in-time observation.  The planner uses the first
// observation to protect images and Collect obtains a fresh observation for
// every deletion, closing the stale-inventory race at the provider boundary.
type RuntimeUse struct {
	Image        domain.ImageDigest `json:"image"`
	InUse        bool               `json:"in_use"`
	DeploymentID string             `json:"deployment_id,omitempty"`
}

func (u RuntimeUse) validate() error {
	if err := u.Image.Validate(); err != nil {
		return fmt.Errorf("%w: runtime image is invalid: %v", ErrInvalidInventory, err)
	}
	return nil
}

type DiskUsage struct {
	TotalBytes     int64     `json:"total_bytes"`
	UsedBytes      int64     `json:"used_bytes"`
	AvailableBytes int64     `json:"available_bytes"`
	ObservedAt     time.Time `json:"observed_at"`
}

func (d DiskUsage) validate() error {
	if d.TotalBytes <= 0 || d.UsedBytes < 0 || d.AvailableBytes < 0 || d.UsedBytes > d.TotalBytes || d.AvailableBytes > d.TotalBytes {
		return fmt.Errorf("%w: disk usage values are inconsistent", ErrInvalidInventory)
	}
	return nil
}

// Inventory is read-only.  Implementations should obtain all values from one
// consistent snapshot where possible; Collect still refreshes runtime use
// immediately before every DeleteImage call.
type Inventory interface {
	ListResources(context.Context) ([]Resource, error)
	ListReleases(context.Context) ([]ReleaseRecord, error)
	ListBuilds(context.Context) ([]BuildRecord, error)
	ListRuntimeUse(context.Context) ([]RuntimeUse, error)
	DiskUsage(context.Context) (DiskUsage, error)
}

// ImageDeleter has the narrowest possible mutation surface.  In particular,
// it cannot delete volumes, networks, containers, or arbitrary paths.
type ImageDeleter interface {
	DeleteImage(context.Context, domain.ImageDigest) error
}

type WatermarkLevel string

const (
	WatermarkBelowSoft WatermarkLevel = "below_soft"
	WatermarkSoft      WatermarkLevel = "soft"
	WatermarkHard      WatermarkLevel = "hard"
)

type Config struct {
	KeepSuccessfulReleases int
	SoftWatermarkPercent   int64
	HardWatermarkPercent   int64
	MinFreeBytes           int64
	HardMinFreeBytes       int64
	Clock                  func() time.Time
}

func DefaultConfig() Config {
	return Config{
		KeepSuccessfulReleases: DefaultKeepSuccessfulReleases,
		SoftWatermarkPercent:   DefaultSoftWatermarkPercent,
		HardWatermarkPercent:   DefaultHardWatermarkPercent,
		Clock:                  func() time.Time { return time.Now().UTC() },
	}
}

func (c Config) normalized() (Config, error) {
	d := DefaultConfig()
	if c.KeepSuccessfulReleases == 0 {
		c.KeepSuccessfulReleases = d.KeepSuccessfulReleases
	}
	if c.SoftWatermarkPercent == 0 {
		c.SoftWatermarkPercent = d.SoftWatermarkPercent
	}
	if c.HardWatermarkPercent == 0 {
		c.HardWatermarkPercent = d.HardWatermarkPercent
	}
	if c.Clock == nil {
		c.Clock = d.Clock
	}
	if c.KeepSuccessfulReleases < 3 || c.SoftWatermarkPercent <= 0 || c.HardWatermarkPercent <= 0 || c.SoftWatermarkPercent >= c.HardWatermarkPercent || c.HardWatermarkPercent > 100 || c.MinFreeBytes < 0 || c.HardMinFreeBytes < 0 || (c.MinFreeBytes > 0 && c.HardMinFreeBytes > c.MinFreeBytes) {
		return Config{}, fmt.Errorf("%w: retain at least current plus two successful releases and use ordered watermarks", ErrInvalidConfig)
	}
	return c, nil
}

type WatermarkDecision struct {
	Level          WatermarkLevel `json:"level"`
	Triggered      bool           `json:"triggered"`
	UsagePercent   int64          `json:"usage_percent"`
	AvailableBytes int64          `json:"available_bytes"`
	Reason         string         `json:"reason,omitempty"`
}

func EvaluateWatermark(usage DiskUsage, config Config) (WatermarkDecision, error) {
	c, err := config.normalized()
	if err != nil {
		return WatermarkDecision{}, err
	}
	if err := usage.validate(); err != nil {
		return WatermarkDecision{}, err
	}
	percent := usagePercent(usage.UsedBytes, usage.TotalBytes)
	hard := atLeastPercent(usage.UsedBytes, usage.TotalBytes, c.HardWatermarkPercent) || (c.HardMinFreeBytes > 0 && usage.AvailableBytes <= c.HardMinFreeBytes)
	soft := atLeastPercent(usage.UsedBytes, usage.TotalBytes, c.SoftWatermarkPercent) || (c.MinFreeBytes > 0 && usage.AvailableBytes <= c.MinFreeBytes)
	decision := WatermarkDecision{Level: WatermarkBelowSoft, UsagePercent: percent, AvailableBytes: usage.AvailableBytes}
	if hard {
		decision.Level, decision.Triggered, decision.Reason = WatermarkHard, true, "hard disk watermark reached"
	} else if soft {
		decision.Level, decision.Triggered, decision.Reason = WatermarkSoft, true, "soft disk watermark reached"
	}
	return decision, nil
}

func usagePercent(used, total int64) int64 {
	// big.Int avoids overflow for very large filesystems while preserving the
	// exact integer threshold used by the collection policy.
	numerator := new(big.Int).Mul(big.NewInt(used), big.NewInt(100))
	numerator.Quo(numerator, big.NewInt(total))
	return numerator.Int64()
}

func atLeastPercent(value, total, percent int64) bool {
	if percent <= 0 {
		return true
	}
	whole := total / 100
	threshold := whole * percent
	rem := total % 100
	threshold += (rem*percent + 99) / 100
	return value >= threshold
}

type ProtectionReason string

const (
	ProtectCurrentRelease    ProtectionReason = "current-release"
	ProtectSuccessfulRelease ProtectionReason = "successful-release"
	ProtectInProgressRelease ProtectionReason = "in-progress-release"
	ProtectRollbackRelease   ProtectionReason = "rollback-release"
	ProtectInProgressBuild   ProtectionReason = "in-progress-build"
	ProtectRuntimeUse        ProtectionReason = "runtime-use"
)

type CandidateReason string

const (
	CandidateFailedBuild CandidateReason = "failed-build"
	CandidateWatermark   CandidateReason = "watermark"
)

type ProtectedImage struct {
	Image   domain.ImageDigest `json:"image"`
	Reasons []ProtectionReason `json:"reasons"`
}

type ImageCandidate struct {
	Image     domain.ImageDigest `json:"image"`
	SizeBytes int64              `json:"size_bytes"`
	CreatedAt time.Time          `json:"created_at"`
	BuildID   string             `json:"build_id,omitempty"`
	Reason    CandidateReason    `json:"reason"`
}

type Plan struct {
	GeneratedAt     time.Time         `json:"generated_at"`
	Disk            DiskUsage         `json:"disk"`
	Watermark       WatermarkDecision `json:"watermark"`
	Protected       []ProtectedImage  `json:"protected"`
	Candidates      []ImageCandidate  `json:"candidates"`
	VolumeCount     int               `json:"volume_count"`
	ImageCount      int               `json:"image_count"`
	FailedBuildRefs int               `json:"failed_build_refs"`
}

type DeleteOutcome struct {
	Candidate ImageCandidate `json:"candidate"`
	Action    string         `json:"action"`
	Reason    string         `json:"reason,omitempty"`
	Error     string         `json:"error,omitempty"`
}

type CollectResult struct {
	Plan     Plan            `json:"plan"`
	Outcomes []DeleteOutcome `json:"outcomes"`
}

func (r CollectResult) Deleted() []ImageCandidate {
	items := make([]ImageCandidate, 0)
	for _, outcome := range r.Outcomes {
		if outcome.Action == "deleted" {
			items = append(items, outcome.Candidate)
		}
	}
	return items
}

func (r CollectResult) Skipped() []DeleteOutcome {
	items := make([]DeleteOutcome, 0)
	for _, outcome := range r.Outcomes {
		if outcome.Action == "skipped" {
			items = append(items, outcome)
		}
	}
	return items
}

// Provider owns only policy and sequencing; inventory and deletion remain
// injected so no test or caller can accidentally give this package a Docker
// socket or a volume deletion capability.
type Provider struct {
	config    Config
	inventory Inventory
	deleter   ImageDeleter
}

func New(config Config, inventory Inventory, deleter ImageDeleter) (*Provider, error) {
	config, err := config.normalized()
	if err != nil {
		return nil, err
	}
	if inventory == nil || deleter == nil {
		return nil, fmt.Errorf("%w: inventory and image deleter are required", ErrInvalidConfig)
	}
	return &Provider{config: config, inventory: inventory, deleter: deleter}, nil
}

// Plan reads a complete inventory and computes a deterministic, fail-closed
// candidate list.  Failed-build images are eligible even below the disk
// watermark; ordinary unreferenced images require the soft watermark.
func (p *Provider) Plan(ctx context.Context) (Plan, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := contextError(ctx); err != nil {
		return Plan{}, err
	}
	resources, err := p.inventory.ListResources(ctx)
	if err != nil {
		return Plan{}, fmt.Errorf("list image GC resources: %w", err)
	}
	releases, err := p.inventory.ListReleases(ctx)
	if err != nil {
		return Plan{}, fmt.Errorf("list image GC releases: %w", err)
	}
	builds, err := p.inventory.ListBuilds(ctx)
	if err != nil {
		return Plan{}, fmt.Errorf("list image GC builds: %w", err)
	}
	runtime, err := p.inventory.ListRuntimeUse(ctx)
	if err != nil {
		return Plan{}, fmt.Errorf("list image GC runtime use: %w", err)
	}
	disk, err := p.inventory.DiskUsage(ctx)
	if err != nil {
		return Plan{}, fmt.Errorf("read image GC disk usage: %w", err)
	}
	watermark, err := EvaluateWatermark(disk, p.config)
	if err != nil {
		return Plan{}, err
	}
	protected, failedBuildImages, failedBuildIDs, inProgressBuildIDs, err := protectionSets(releases, builds, runtime, p.config.KeepSuccessfulReleases)
	if err != nil {
		return Plan{}, err
	}
	imageResources := make([]Resource, 0, len(resources))
	volumeCount := 0
	for _, resource := range resources {
		if err := resource.validate(); err != nil {
			return Plan{}, err
		}
		if resource.Kind == ResourceVolume {
			volumeCount++
			continue
		}
		imageResources = append(imageResources, resource)
	}
	sort.Slice(imageResources, func(i, j int) bool { return resourceLess(imageResources[i], imageResources[j]) })
	seen := make(map[string]struct{}, len(imageResources))
	candidates := make([]ImageCandidate, 0, len(imageResources))
	for _, resource := range imageResources {
		key := imageKey(resource.Image)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		if _, ok := protected[key]; ok {
			continue
		}
		reason := CandidateFailedBuild
		failed := false
		if _, ok := failedBuildImages[key]; ok {
			failed = true
		} else if resource.BuildID != "" {
			_, failed = failedBuildIDs[resource.BuildID]
		}
		if !failed {
			if resource.BuildID != "" {
				if _, inProgress := inProgressBuildIDs[resource.BuildID]; inProgress {
					// A build-level reference is protected even if the adapter did
					// not include its image in BuildRecord.Images.
					continue
				}
			}
			if !watermark.Triggered {
				continue
			}
			reason = CandidateWatermark
		}
		candidates = append(candidates, ImageCandidate{Image: cleanImage(resource.Image), SizeBytes: resource.SizeBytes, CreatedAt: resource.CreatedAt.UTC(), BuildID: resource.BuildID, Reason: reason})
	}
	protectedList := make([]ProtectedImage, 0, len(protected))
	for key, reasons := range protected {
		protectedList = append(protectedList, ProtectedImage{Image: keyToImage(key), Reasons: append([]ProtectionReason(nil), reasons...)})
	}
	sort.Slice(protectedList, func(i, j int) bool { return imageKey(protectedList[i].Image) < imageKey(protectedList[j].Image) })
	for i := range protectedList {
		sort.Slice(protectedList[i].Reasons, func(a, b int) bool { return protectedList[i].Reasons[a] < protectedList[i].Reasons[b] })
	}
	sort.Slice(candidates, func(i, j int) bool { return candidateLess(candidates[i], candidates[j]) })
	return Plan{
		GeneratedAt:     p.config.Clock().UTC(),
		Disk:            disk,
		Watermark:       watermark,
		Protected:       protectedList,
		Candidates:      candidates,
		VolumeCount:     volumeCount,
		ImageCount:      len(imageResources),
		FailedBuildRefs: len(failedBuildImages),
	}, nil
}

// Collect plans once and rechecks runtime references immediately before every
// deletion.  A concurrent runtime reference therefore becomes a skip, never
// an image deletion.  Deletion errors are returned after all safe candidates
// have been attempted so one stale object does not prevent cleanup of others.
func (p *Provider) Collect(ctx context.Context) (CollectResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	plan, err := p.Plan(ctx)
	if err != nil {
		return CollectResult{}, err
	}
	result := CollectResult{Plan: plan, Outcomes: make([]DeleteOutcome, 0, len(plan.Candidates))}
	var deleteErrors []error
	for _, candidate := range plan.Candidates {
		if err := contextError(ctx); err != nil {
			return result, err
		}
		runtime, err := p.inventory.ListRuntimeUse(ctx)
		if err != nil {
			return result, fmt.Errorf("recheck image GC runtime use for %s: %w", imageKey(candidate.Image), err)
		}
		inUse, err := runtimeUsesImage(runtime, candidate.Image)
		if err != nil {
			return result, err
		}
		if inUse {
			result.Outcomes = append(result.Outcomes, DeleteOutcome{Candidate: candidate, Action: "skipped", Reason: "runtime-reference-reappeared"})
			continue
		}
		if err := p.deleter.DeleteImage(ctx, candidate.Image); err != nil {
			result.Outcomes = append(result.Outcomes, DeleteOutcome{Candidate: candidate, Action: "failed", Reason: "image-deletion-failed", Error: err.Error()})
			deleteErrors = append(deleteErrors, fmt.Errorf("delete image %s: %w", imageKey(candidate.Image), err))
			continue
		}
		result.Outcomes = append(result.Outcomes, DeleteOutcome{Candidate: candidate, Action: "deleted"})
	}
	if len(deleteErrors) > 0 {
		return result, errors.Join(deleteErrors...)
	}
	return result, nil
}

func protectionSets(releases []ReleaseRecord, builds []BuildRecord, runtime []RuntimeUse, keep int) (map[string][]ProtectionReason, map[string]struct{}, map[string]struct{}, map[string]struct{}, error) {
	for _, release := range releases {
		if err := release.validate(); err != nil {
			return nil, nil, nil, nil, err
		}
	}
	for _, build := range builds {
		if err := build.validate(); err != nil {
			return nil, nil, nil, nil, err
		}
	}
	for _, use := range runtime {
		if err := use.validate(); err != nil {
			return nil, nil, nil, nil, err
		}
	}
	protected := make(map[string][]ProtectionReason)
	add := func(image domain.ImageDigest, reason ProtectionReason) {
		key := imageKey(image)
		for _, existing := range protected[key] {
			if existing == reason {
				return
			}
		}
		protected[key] = append(protected[key], reason)
	}
	successful := make([]ReleaseRecord, 0, len(releases))
	currentReleaseIDs := make(map[string]struct{})
	for _, release := range releases {
		if release.isCurrent() {
			currentReleaseIDs[release.ID] = struct{}{}
			for _, image := range release.Images {
				add(image, ProtectCurrentRelease)
			}
		}
		if release.isInProgress() {
			for _, image := range release.Images {
				add(image, ProtectInProgressRelease)
			}
		}
		if release.isRollback() {
			for _, image := range release.Images {
				add(image, ProtectRollbackRelease)
			}
		}
		if release.isSuccessful() {
			successful = append(successful, release)
		}
	}
	sort.Slice(successful, func(i, j int) bool {
		if !successful[i].CreatedAt.Equal(successful[j].CreatedAt) {
			return successful[i].CreatedAt.After(successful[j].CreatedAt)
		}
		return successful[i].ID > successful[j].ID
	})
	// Current is retained independently.  When a current release exists,
	// retain the latest two other successful releases so the policy is exactly
	// "current plus latest two successful", even while the current rollout is
	// still in progress.  If no current release is reported, retain the normal
	// latest three successful releases as a conservative fail-closed fallback.
	limit := keep
	if len(currentReleaseIDs) > 0 {
		limit = keep - 1
	}
	selected := 0
	for _, release := range successful {
		if _, current := currentReleaseIDs[release.ID]; current {
			continue
		}
		if selected >= limit {
			break
		}
		for _, image := range release.Images {
			add(image, ProtectSuccessfulRelease)
		}
		selected++
	}
	failedBuildImages := make(map[string]struct{})
	failedBuildIDs := make(map[string]struct{})
	inProgressBuildIDs := make(map[string]struct{})
	for _, build := range builds {
		switch build.Status {
		case BuildPending, BuildRunning, BuildInProgress:
			inProgressBuildIDs[build.ID] = struct{}{}
			for _, image := range build.Images {
				add(image, ProtectInProgressBuild)
			}
		case BuildFailed:
			failedBuildIDs[build.ID] = struct{}{}
			for _, image := range build.Images {
				failedBuildImages[imageKey(image)] = struct{}{}
			}
		}
	}
	for _, use := range runtime {
		if use.InUse {
			add(use.Image, ProtectRuntimeUse)
		}
	}
	return protected, failedBuildImages, failedBuildIDs, inProgressBuildIDs, nil
}

func runtimeUsesImage(runtime []RuntimeUse, image domain.ImageDigest) (bool, error) {
	for _, use := range runtime {
		if err := use.validate(); err != nil {
			return false, err
		}
		if use.InUse && imageKey(use.Image) == imageKey(image) {
			return true, nil
		}
	}
	return false, nil
}

func resourceLess(a, b Resource) bool {
	ak, bk := imageKey(a.Image), imageKey(b.Image)
	if ak != bk {
		return ak < bk
	}
	if !a.CreatedAt.Equal(b.CreatedAt) {
		return a.CreatedAt.Before(b.CreatedAt)
	}
	if a.SizeBytes != b.SizeBytes {
		return a.SizeBytes < b.SizeBytes
	}
	return a.BuildID < b.BuildID
}

func candidateLess(a, b ImageCandidate) bool {
	if !a.CreatedAt.Equal(b.CreatedAt) {
		return a.CreatedAt.Before(b.CreatedAt)
	}
	return imageKey(a.Image) < imageKey(b.Image)
}

func imageKey(image domain.ImageDigest) string {
	return image.Repository + "@" + image.Digest
}

// ImageKey returns the stable repository@digest identity used by plans and
// evidence.  The tag annotation is intentionally excluded.
func ImageKey(image domain.ImageDigest) string { return imageKey(image) }

func keyToImage(key string) domain.ImageDigest {
	parts := strings.SplitN(key, "@", 2)
	if len(parts) != 2 {
		return domain.ImageDigest{}
	}
	return domain.ImageDigest{Repository: parts[0], Digest: parts[1]}
}

func cleanImage(image domain.ImageDigest) domain.ImageDigest {
	return domain.ImageDigest{Repository: image.Repository, Digest: image.Digest}
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	return ctx.Err()
}
