package runner

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/moby/moby/api/pkg/stdcopy"
	"github.com/moby/moby/api/types/build"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"
	"github.com/moby/moby/api/types/network"
	"github.com/moby/moby/client"
)

// buildMemoryBytes bounds the memory available to a build; large enough for
// typical language toolchains, small enough to protect the host.
const buildMemoryBytes = 2 << 30

// ansiPattern strips terminal color/cursor escape codes from log lines.
var ansiPattern = regexp.MustCompile(`\x1b\[[0-9;]*[A-Za-z]`)

// Build classification heuristics mirror the N0 prototype.
var (
	missingModulePattern = regexp.MustCompile(`(?i)(ModuleNotFoundError|Cannot find module|no required module|not found: )`)
	pullFailurePattern   = regexp.MustCompile(`(?i)(pull access denied|manifest unknown|manifest for .* not found|TLS handshake timeout|i/o timeout|dial tcp|context deadline exceeded|failed to resolve|no such host)`)
)

// Docker implements API against a local Docker daemon. It only ever touches
// objects carrying LabelManaged=1 and never creates privileged, host-network
// or bind-mounted containers.
type Docker struct {
	cli *client.Client

	// mu guards inflight, the concurrent-build dedupe map.
	mu       sync.Mutex
	inflight map[string]*buildCall
}

// buildCall is one shared, in-flight build keyed by image tag (singleflight).
type buildCall struct {
	done chan struct{}
	resp BuildResponse
	err  error
}

// NewDocker returns a Docker-backed API. The caller owns cli.
func NewDocker(cli *client.Client) *Docker {
	return &Docker{cli: cli, inflight: map[string]*buildCall{}}
}

// Ping reports the Docker API and server versions.
func (d *Docker) Ping(ctx context.Context) (PingResponse, error) {
	ping, err := d.cli.Ping(ctx, client.PingOptions{})
	if err != nil {
		return PingResponse{}, err
	}
	resp := PingResponse{DockerAPIVersion: ping.APIVersion}
	if ver, err := d.cli.ServerVersion(ctx, client.ServerVersionOptions{}); err == nil {
		resp.ServerVersion = ver.Version
		if resp.DockerAPIVersion == "" {
			resp.DockerAPIVersion = ver.APIVersion
		}
	}
	return resp, nil
}

// Build builds ImageTag(App, DeploymentID) from a tar or tar.gz on disk. If the
// tag already exists it is returned without building. Concurrent identical
// requests share a single build.
func (d *Docker) Build(ctx context.Context, req BuildRequest) (BuildResponse, error) {
	tag := ImageTag(req.App, req.DeploymentID)

	// Fast path: a previous build already produced this tag.
	if info, err := d.inspectImage(ctx, tag, req.App); err == nil {
		return BuildResponse{OK: true, Image: &info}, nil
	} else if !cerrdefs.IsNotFound(err) {
		return BuildResponse{}, err
	}

	// Deduplicate concurrent identical builds by tag.
	d.mu.Lock()
	if call, ok := d.inflight[tag]; ok {
		d.mu.Unlock()
		select {
		case <-call.done:
			return call.resp, call.err
		case <-ctx.Done():
			return BuildResponse{}, ctx.Err()
		}
	}
	call := &buildCall{done: make(chan struct{})}
	d.inflight[tag] = call
	d.mu.Unlock()

	call.resp, call.err = d.runBuild(ctx, req, tag)
	close(call.done)

	d.mu.Lock()
	delete(d.inflight, tag)
	d.mu.Unlock()

	return call.resp, call.err
}

// runBuild performs a single build: it reads the upload, validates the presence
// of a Dockerfile at the context root, streams the build and classifies the
// result. User-caused failures come back as BuildResponse{OK:false}; daemon or
// transport failures come back as an error.
func (d *Docker) runBuild(ctx context.Context, req BuildRequest, tag string) (BuildResponse, error) {
	raw, err := os.ReadFile(req.ContextPath)
	if err != nil {
		return BuildResponse{OK: false, Failure: &Failure{
			Stage: "upload", Code: "upload_invalid",
			Message: "无法读取上传的项目包",
			Hint:    "使用 acornfox deploy 重新上传项目目录",
		}}, nil
	}

	tarBytes, hasDockerfile, err := normalizeContext(raw)
	if err != nil {
		return BuildResponse{OK: false, Failure: &Failure{
			Stage: "upload", Code: "upload_invalid",
			Message: "上传的内容不是有效的 tar 或 tar.gz 目录包",
			Hint:    "使用 acornfox deploy 上传项目目录",
		}}, nil
	}
	if !hasDockerfile {
		return BuildResponse{OK: false, Failure: &Failure{
			Stage: "upload", Code: "dockerfile_missing",
			Message: "项目根目录没有 Dockerfile",
			Hint:    "在项目根目录添加 Dockerfile（写明 EXPOSE 端口）后重新部署",
		}}, nil
	}

	labels := map[string]string{
		LabelManaged:    "1",
		LabelApp:        req.App,
		LabelDeployment: req.DeploymentID,
	}
	result, err := d.cli.ImageBuild(ctx, bytes.NewReader(tarBytes), client.ImageBuildOptions{
		Tags:        []string{tag},
		Remove:      true,
		ForceRemove: true,
		Labels:      labels,
		Version:     build.BuilderV1,
		Memory:      buildMemoryBytes,
	})
	if err != nil {
		return BuildResponse{}, err
	}
	defer result.Body.Close()

	lines, buildErr := drainBuild(result.Body)
	if buildErr != nil {
		return BuildResponse{OK: false, Failure: classifyBuild(buildErr, lines)}, nil
	}

	info, err := d.inspectImage(ctx, tag, req.App)
	if err != nil {
		if cerrdefs.IsNotFound(err) {
			return BuildResponse{OK: false, Failure: &Failure{
				Stage: "build", Code: "build_failed",
				Message: "构建结束但没有生成镜像",
				Hint:    "检查 Dockerfile 是否成功产出镜像后重新部署",
			}}, nil
		}
		return BuildResponse{}, err
	}
	return BuildResponse{OK: true, Image: &info}, nil
}

// buildMessage is one line of the BuilderV1 JSON stream.
type buildMessage struct {
	Stream      string `json:"stream"`
	Error       string `json:"error"`
	ErrorDetail struct {
		Message string `json:"message"`
	} `json:"errorDetail"`
}

// drainBuild consumes the build stream, collecting output lines and returning
// the first error the daemon reports.
func drainBuild(r io.Reader) ([]string, error) {
	var lines []string
	dec := json.NewDecoder(r)
	for {
		var m buildMessage
		if err := dec.Decode(&m); err == io.EOF {
			break
		} else if err != nil {
			return lines, err
		}
		for _, l := range strings.Split(strings.TrimRight(m.Stream, "\n"), "\n") {
			if strings.TrimSpace(l) != "" {
				lines = append(lines, l)
			}
		}
		if m.Error != "" {
			return lines, errors.New(m.Error)
		}
	}
	return lines, nil
}

// buildExcerpt keeps the output of the failing step, stripped of Docker's step
// bookkeeping and terminal color codes, capped at MaxLogExcerptLine lines.
func buildExcerpt(lines []string) string {
	start := 0
	for i, l := range lines {
		if strings.HasPrefix(l, "Step ") {
			start = i
		}
	}
	var out []string
	for _, l := range lines[start:] {
		l = strings.TrimRight(ansiPattern.ReplaceAllString(l, ""), " ")
		if strings.HasPrefix(strings.TrimSpace(l), "--->") || strings.TrimSpace(l) == "" {
			continue
		}
		out = append(out, l)
	}
	return tailLines(out, MaxLogExcerptLine)
}

// classifyBuild turns a build error and its logs into a structured Failure.
func classifyBuild(err error, lines []string) *Failure {
	excerpt := buildExcerpt(lines)
	all := err.Error() + "\n" + excerpt
	f := &Failure{
		Stage:      "build",
		Code:       "build_failed",
		Message:    "镜像构建失败: " + ansiPattern.ReplaceAllString(err.Error(), ""),
		LogExcerpt: excerpt,
		Hint:       "根据日志修改 Dockerfile 或依赖后重新部署",
	}
	switch {
	case pullFailurePattern.MatchString(all):
		f.Code = "base_image_not_found"
		f.Hint = "基础镜像拉取失败：检查镜像名，或为服务器配置镜像加速后重试"
	case missingModulePattern.MatchString(all):
		f.Code = "dependency_missing"
		f.Hint = "构建缺少依赖：把依赖写进依赖清单（如 requirements.txt / package.json）并在 Dockerfile 中安装"
	}
	return f
}

// normalizeContext returns a plain tar (decompressing gzip if detected) and
// whether it contains a Dockerfile at the context root.
func normalizeContext(raw []byte) ([]byte, bool, error) {
	if isGzip(raw) {
		zr, err := gzip.NewReader(bytes.NewReader(raw))
		if err != nil {
			return nil, false, err
		}
		defer zr.Close()
		decoded, err := io.ReadAll(zr)
		if err != nil {
			return nil, false, err
		}
		raw = decoded
	}
	has, err := scanTarForRootDockerfile(raw)
	if err != nil {
		return nil, false, err
	}
	return raw, has, nil
}

// isGzip reports whether b starts with the gzip magic bytes.
func isGzip(b []byte) bool {
	return len(b) >= 2 && b[0] == 0x1f && b[1] == 0x8b
}

// ImageInspect returns the managed image identified by ref (a tag or ID).
func (d *Docker) ImageInspect(ctx context.Context, app, ref string) (ImageInfo, error) {
	info, err := d.inspectImage(ctx, ref, app)
	if err != nil {
		if cerrdefs.IsNotFound(err) {
			return ImageInfo{}, ErrNotFound
		}
		return ImageInfo{}, err
	}
	return info, nil
}

// inspectImage inspects ref and verifies it is a managed image of app.
func (d *Docker) inspectImage(ctx context.Context, ref, app string) (ImageInfo, error) {
	res, err := d.cli.ImageInspect(ctx, ref)
	if err != nil {
		return ImageInfo{}, err
	}
	info := imageInfoFromInspect(res)
	if info.App != app {
		// Not a managed image of this app: treat as absent.
		return ImageInfo{}, cerrdefs.ErrNotFound
	}
	return info, nil
}

// imageInfoFromInspect maps a Docker image inspect into ImageInfo.
func imageInfoFromInspect(res client.ImageInspectResult) ImageInfo {
	info := ImageInfo{
		ID:   res.ID,
		Tags: res.RepoTags,
		Size: res.Size,
	}
	if ts, err := time.Parse(time.RFC3339Nano, res.Created); err == nil {
		info.Created = ts.Unix()
	}
	if res.Config != nil {
		labels := res.Config.Labels
		info.App = labels[LabelApp]
		info.DeploymentID = labels[LabelDeployment]
		info.ExposedPorts = sortedTCPPorts(res.Config.ExposedPorts)
		info.Volumes = sortedKeys(res.Config.Volumes)
	}
	return info
}

// sortedTCPPorts returns ascending TCP port numbers from an ExposedPorts set.
func sortedTCPPorts(ports map[string]struct{}) []int {
	var out []int
	for spec := range ports {
		p, err := network.ParsePort(spec)
		if err != nil || p.Proto() != network.TCP {
			continue
		}
		out = append(out, int(p.Num()))
	}
	sort.Ints(out)
	return out
}

// sortedKeys returns the sorted keys of a set.
func sortedKeys(set map[string]struct{}) []string {
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ListImages lists managed images, optionally filtered to one app.
func (d *Docker) ListImages(ctx context.Context, app string) ([]ImageInfo, error) {
	filters := client.Filters{}.Add("label", LabelManaged+"=1")
	if app != "" {
		filters = filters.Add("label", LabelApp+"="+app)
	}
	res, err := d.cli.ImageList(ctx, client.ImageListOptions{Filters: filters})
	if err != nil {
		return nil, err
	}
	var out []ImageInfo
	for _, summary := range res.Items {
		if summary.Labels[LabelManaged] != "1" {
			continue
		}
		info, err := d.inspectImage(ctx, summary.ID, summary.Labels[LabelApp])
		if err != nil {
			continue
		}
		out = append(out, info)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Created > out[j].Created })
	return out, nil
}

// RemoveImage removes a managed image of app. Missing is success.
func (d *Docker) RemoveImage(ctx context.Context, app, ref string) error {
	if _, err := d.inspectImage(ctx, ref, app); err != nil {
		if cerrdefs.IsNotFound(err) {
			return nil
		}
		return err
	}
	_, err := d.cli.ImageRemove(ctx, ref, client.ImageRemoveOptions{PruneChildren: true})
	if err != nil && cerrdefs.IsNotFound(err) {
		return nil
	}
	return err
}

// EnsureContainer creates the container if absent (idempotent by name), starts
// it if not running, and returns its observed state.
func (d *Docker) EnsureContainer(ctx context.Context, req EnsureContainerRequest) (ContainerInfo, error) {
	name := ContainerName(req.App, req.DeploymentID)

	// If it already exists, reuse it as-is (name is the idempotency key).
	inspect, err := d.cli.ContainerInspect(ctx, name, client.ContainerInspectOptions{})
	if err == nil {
		if err := d.startIfNeeded(ctx, name, inspect); err != nil {
			return ContainerInfo{}, err
		}
		return d.containerInfo(ctx, name)
	}
	if !cerrdefs.IsNotFound(err) {
		return ContainerInfo{}, err
	}

	if err := d.ensureNetwork(ctx, req.App); err != nil {
		return ContainerInfo{}, err
	}

	containerPort, ok := network.PortFrom(uint16(req.Port), network.TCP)
	if !ok {
		return ContainerInfo{}, fmt.Errorf("invalid container port %d", req.Port)
	}

	mounts, err := buildMounts(req.App, req.Mounts)
	if err != nil {
		return ContainerInfo{}, err
	}

	labels := map[string]string{
		LabelManaged:    "1",
		LabelApp:        req.App,
		LabelDeployment: req.DeploymentID,
		LabelRole:       RoleApp,
	}
	pids := int64(DefaultPidsLimit)
	memory := int64(req.MemoryMB) * (1 << 20)
	nanoCPUs := int64(req.CPUMilli) * 1e6

	created, err := d.cli.ContainerCreate(ctx, client.ContainerCreateOptions{
		Name: name,
		Config: &container.Config{
			Image:        req.Image,
			Labels:       labels,
			Env:          envSlice(req.Env),
			ExposedPorts: network.PortSet{containerPort: {}},
		},
		HostConfig: &container.HostConfig{
			NetworkMode: container.NetworkMode(NetworkName(req.App)),
			// Publish only on loopback; Caddy is the public entry point.
			PortBindings: network.PortMap{containerPort: {{
				HostIP:   netip.MustParseAddr("127.0.0.1"),
				HostPort: "0",
			}}},
			RestartPolicy: container.RestartPolicy{Name: container.RestartPolicyUnlessStopped},
			SecurityOpt:   []string{"no-new-privileges"},
			LogConfig: container.LogConfig{
				Type:   "json-file",
				Config: map[string]string{"max-size": LogMaxSize, "max-file": LogMaxFiles},
			},
			Resources: container.Resources{
				Memory:    memory,
				NanoCPUs:  nanoCPUs,
				PidsLimit: &pids,
			},
			Privileged: false,
			Mounts:     mounts,
		},
	})
	if err != nil {
		// A concurrent create may have won the race; reuse the existing one.
		if cerrdefs.IsConflict(err) {
			if _, ierr := d.cli.ContainerInspect(ctx, name, client.ContainerInspectOptions{}); ierr == nil {
				if serr := d.startByName(ctx, name); serr != nil {
					return ContainerInfo{}, serr
				}
				return d.containerInfo(ctx, name)
			}
		}
		return ContainerInfo{}, err
	}

	if _, err := d.cli.ContainerStart(ctx, created.ID, client.ContainerStartOptions{}); err != nil {
		return ContainerInfo{}, err
	}
	return d.containerInfo(ctx, name)
}

// startIfNeeded starts an existing container only if it is not already running.
func (d *Docker) startIfNeeded(ctx context.Context, name string, inspect client.ContainerInspectResult) error {
	if inspect.Container.State != nil && inspect.Container.State.Running {
		return nil
	}
	return d.startByName(ctx, name)
}

// startByName starts a container by name, treating an already-started container
// as success.
func (d *Docker) startByName(ctx context.Context, name string) error {
	_, err := d.cli.ContainerStart(ctx, name, client.ContainerStartOptions{})
	if err != nil && cerrdefs.IsConflict(err) {
		return nil
	}
	return err
}

// ensureNetwork creates the app's bridge network with managed labels if it does
// not already exist.
func (d *Docker) ensureNetwork(ctx context.Context, app string) error {
	name := NetworkName(app)
	if _, err := d.cli.NetworkInspect(ctx, name, client.NetworkInspectOptions{}); err == nil {
		return nil
	} else if !cerrdefs.IsNotFound(err) {
		return err
	}
	_, err := d.cli.NetworkCreate(ctx, name, client.NetworkCreateOptions{
		Driver: "bridge",
		Labels: map[string]string{LabelManaged: "1", LabelApp: app},
	})
	// Another goroutine may have created it first.
	if err != nil && cerrdefs.IsConflict(err) {
		return nil
	}
	return err
}

// buildMounts converts request mounts into named-volume mounts, refusing any
// volume whose name is not prefixed with VolumePrefix(app).
func buildMounts(app string, in []Mount) ([]mount.Mount, error) {
	prefix := VolumePrefix(app)
	var out []mount.Mount
	for _, m := range in {
		if !strings.HasPrefix(m.Volume, prefix) {
			return nil, fmt.Errorf("mount volume %q must start with %q", m.Volume, prefix)
		}
		if !path.IsAbs(m.Path) || path.Clean(m.Path) != m.Path {
			return nil, fmt.Errorf("mount path %q must be absolute and clean", m.Path)
		}
		out = append(out, mount.Mount{
			Type:   mount.TypeVolume,
			Source: m.Volume,
			Target: m.Path,
		})
	}
	return out, nil
}

// envSlice converts an env map into a sorted KEY=VALUE slice.
func envSlice(env map[string]string) []string {
	if len(env) == 0 {
		return nil
	}
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(env))
	for _, k := range keys {
		out = append(out, k+"="+env[k])
	}
	return out
}

// ListContainers lists managed containers, optionally filtered to one app.
func (d *Docker) ListContainers(ctx context.Context, app string) ([]ContainerInfo, error) {
	filters := client.Filters{}.Add("label", LabelManaged+"=1")
	if app != "" {
		filters = filters.Add("label", LabelApp+"="+app)
	}
	res, err := d.cli.ContainerList(ctx, client.ContainerListOptions{All: true, Filters: filters})
	if err != nil {
		return nil, err
	}
	var out []ContainerInfo
	for _, summary := range res.Items {
		if summary.Labels[LabelManaged] != "1" {
			continue
		}
		info, err := d.containerInfoByID(ctx, summary.ID)
		if err != nil {
			if cerrdefs.IsNotFound(err) {
				continue
			}
			return nil, err
		}
		out = append(out, info)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// containerInfo inspects a container by name and maps it to ContainerInfo.
func (d *Docker) containerInfo(ctx context.Context, name string) (ContainerInfo, error) {
	return d.containerInfoByID(ctx, name)
}

// containerInfoByID inspects a container and maps its observed state.
func (d *Docker) containerInfoByID(ctx context.Context, id string) (ContainerInfo, error) {
	res, err := d.cli.ContainerInspect(ctx, id, client.ContainerInspectOptions{})
	if err != nil {
		return ContainerInfo{}, err
	}
	c := res.Container
	info := ContainerInfo{
		ID:           c.ID,
		Name:         strings.TrimPrefix(c.Name, "/"),
		Image:        c.Image,
		RestartCount: c.RestartCount,
	}
	if c.Config != nil {
		info.App = c.Config.Labels[LabelApp]
		info.DeploymentID = c.Config.Labels[LabelDeployment]
		info.Role = c.Config.Labels[LabelRole]
	}
	if c.State != nil {
		info.State = string(c.State.Status)
		info.Running = c.State.Running
		info.Restarting = c.State.Restarting
		info.ExitCode = c.State.ExitCode
		info.OOMKilled = c.State.OOMKilled
		info.StartedAt = c.State.StartedAt
	}
	info.HostPort = firstHostPort(c.NetworkSettings)
	return info, nil
}

// firstHostPort returns the loopback host port published for the container, or
// 0 when none is published.
func firstHostPort(ns *container.NetworkSettings) int {
	if ns == nil {
		return 0
	}
	best := 0
	for _, bindings := range ns.Ports {
		for _, b := range bindings {
			p, err := strconv.Atoi(b.HostPort)
			if err != nil || p <= 0 {
				continue
			}
			if best == 0 || p < best {
				best = p
			}
		}
	}
	return best
}

// StopContainer stops a managed container. Missing is success.
func (d *Docker) StopContainer(ctx context.Context, app, name string) error {
	if _, err := d.cli.ContainerInspect(ctx, name, client.ContainerInspectOptions{}); err != nil {
		if cerrdefs.IsNotFound(err) {
			return nil
		}
		return err
	}
	_, err := d.cli.ContainerStop(ctx, name, client.ContainerStopOptions{})
	if err != nil && cerrdefs.IsNotFound(err) {
		return nil
	}
	return err
}

// StartContainer starts a managed container and returns its state.
func (d *Docker) StartContainer(ctx context.Context, app, name string) (ContainerInfo, error) {
	if err := d.startByName(ctx, name); err != nil {
		if cerrdefs.IsNotFound(err) {
			return ContainerInfo{}, ErrNotFound
		}
		return ContainerInfo{}, err
	}
	return d.containerInfo(ctx, name)
}

// RemoveContainer force-removes a managed container. Missing is success.
func (d *Docker) RemoveContainer(ctx context.Context, app, name string) error {
	_, err := d.cli.ContainerRemove(ctx, name, client.ContainerRemoveOptions{Force: true})
	if err != nil && cerrdefs.IsNotFound(err) {
		return nil
	}
	return err
}

// Logs returns the last tail lines of a container's combined output, ANSI
// stripped.
func (d *Docker) Logs(ctx context.Context, app, name string, tail int) ([]string, error) {
	if tail <= 0 {
		tail = 40
	}
	if tail > 1000 {
		tail = 1000
	}
	rc, err := d.cli.ContainerLogs(ctx, name, client.ContainerLogsOptions{
		ShowStdout: true,
		ShowStderr: true,
		Tail:       strconv.Itoa(tail),
	})
	if err != nil {
		if cerrdefs.IsNotFound(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	defer rc.Close()

	var buf bytes.Buffer
	if _, err := stdcopy.StdCopy(&buf, &buf, io.LimitReader(rc, 4<<20)); err != nil {
		return nil, err
	}
	return splitLogLines(buf.Bytes()), nil
}

// splitLogLines splits raw log bytes into ANSI-stripped, non-empty lines.
func splitLogLines(b []byte) []string {
	var out []string
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		line := ansiPattern.ReplaceAllString(sc.Text(), "")
		line = strings.TrimRight(line, "\r")
		out = append(out, line)
	}
	return out
}

// dbFilePattern matches database-like filenames in the container diff.
var dbFilePattern = regexp.MustCompile(`(?i)\.(db|sqlite|sqlite3|db-wal|db-journal)$`)

// Diff returns database-like files added or changed in the writable layer,
// excluding paths under the container's mounts.
func (d *Docker) Diff(ctx context.Context, app, name string) ([]string, error) {
	inspect, err := d.cli.ContainerInspect(ctx, name, client.ContainerInspectOptions{})
	if err != nil {
		if cerrdefs.IsNotFound(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	var mountTargets []string
	for _, mp := range inspect.Container.Mounts {
		if mp.Destination != "" {
			mountTargets = append(mountTargets, path.Clean(mp.Destination))
		}
	}

	res, err := d.cli.ContainerDiff(ctx, name, client.ContainerDiffOptions{})
	if err != nil {
		if cerrdefs.IsNotFound(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	var out []string
	for _, ch := range res.Changes {
		clean := path.Clean(ch.Path)
		base := path.Base(clean)
		if !dbFilePattern.MatchString(base) {
			continue
		}
		if underAnyMount(clean, mountTargets) {
			continue
		}
		out = append(out, clean)
	}
	sort.Strings(out)
	return out, nil
}

// underAnyMount reports whether p is at or under any mount target.
func underAnyMount(p string, targets []string) bool {
	for _, t := range targets {
		if p == t || strings.HasPrefix(p, t+"/") {
			return true
		}
	}
	return false
}

// EnsureVolume creates the named volume if absent. The name must be prefixed
// with VolumePrefix(app).
func (d *Docker) EnsureVolume(ctx context.Context, app, name string) error {
	if !strings.HasPrefix(name, VolumePrefix(app)) {
		return fmt.Errorf("volume %q must start with %q", name, VolumePrefix(app))
	}
	_, err := d.cli.VolumeCreate(ctx, client.VolumeCreateOptions{
		Name:   name,
		Driver: "local",
		Labels: map[string]string{LabelManaged: "1", LabelApp: app},
	})
	return err
}

// ListVolumes lists managed volumes, optionally filtered to one app.
func (d *Docker) ListVolumes(ctx context.Context, app string) ([]VolumeInfo, error) {
	filters := client.Filters{}.Add("label", LabelManaged+"=1")
	if app != "" {
		filters = filters.Add("label", LabelApp+"="+app)
	}
	res, err := d.cli.VolumeList(ctx, client.VolumeListOptions{Filters: filters})
	if err != nil {
		return nil, err
	}
	var out []VolumeInfo
	for _, v := range res.Items {
		if v.Labels[LabelManaged] != "1" {
			continue
		}
		out = append(out, VolumeInfo{
			Name:    v.Name,
			App:     v.Labels[LabelApp],
			Created: v.CreatedAt,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// scanTarForRootDockerfile reports whether the tar stream contains a
// Dockerfile at the context root (./Dockerfile or Dockerfile).
func scanTarForRootDockerfile(raw []byte) (bool, error) {
	tr := tar.NewReader(bytes.NewReader(raw))
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		name := strings.TrimPrefix(h.Name, "./")
		if name == "Dockerfile" {
			return true, nil
		}
	}
}

// tailLines joins the last n lines with newlines.
func tailLines(lines []string, n int) string {
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}
