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
	pullFailurePattern   = regexp.MustCompile(`(?i)(TLS handshake timeout|i/o timeout|dial tcp|context deadline exceeded|no such host|connection reset|connection refused|EOF)`)
	// Package-manager downloads during the build (npm / yarn / pnpm, pip, Go
	// modules, apk, apt). Checked before pullFailurePattern, whose generic
	// network errors would otherwise blame the base image.
	registryTimeoutPattern = regexp.MustCompile(`(?i)(npm (ERR!|error) (code |errno )?(ETIMEDOUT|ECONNRESET|ECONNREFUSED|EAI_AGAIN|ENOTFOUND)|network request to https?://\S*registry|ERR_PNPM_META_FETCH_FAIL|trouble with your network connection|Read timed out|ConnectTimeoutError|Could not fetch URL|Retrying \(Retry\(total=|proxy\.golang\.org|sum\.golang\.org|dl-cdn\.alpinelinux\.org|Failed to fetch https?://\S*(debian|ubuntu)|Could not connect to \S*(debian|ubuntu))`)
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
	case registryTimeoutPattern.MatchString(all):
		f.Code = "registry_timeout"
		f.Hint = "构建时访问软件包源超时。服务器在中国大陆时，在 Dockerfile 中改用国内镜像源后重新部署：npm 加 --registry=https://registry.npmmirror.com；pip 加 -i https://mirrors.aliyun.com/pypi/simple；Go 设 ENV GOPROXY=https://goproxy.cn,direct；Alpine 用 sed -i 's/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g' /etc/apk/repositories"
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

// PullImage pulls an external image Ref and tags it ImageTag(App, DeploymentID).
// If that tag already exists the existing image is returned without pulling.
// A pull that fails for a user-visible reason (image not found, timeout,
// registry error) comes back as PullResponse{OK:false} with a classified
// Failure; daemon/transport problems come back as an error.
func (d *Docker) PullImage(ctx context.Context, app, deploymentID, ref string) (PullResponse, error) {
	tag := ImageTag(app, deploymentID)

	// Fast path: this deployment's tag already exists (idempotent pull).
	if info, err := d.inspectByTag(ctx, app, tag); err == nil {
		return PullResponse{OK: true, Image: &info}, nil
	} else if !cerrdefs.IsNotFound(err) {
		return PullResponse{}, err
	}

	// Bound the pull to pullImageTimeout regardless of the caller's context.
	pctx, cancel := context.WithTimeout(ctx, pullImageTimeout)
	defer cancel()

	resp, err := d.cli.ImagePull(pctx, ref, client.ImagePullOptions{})
	if err != nil {
		if f := classifyPull(pctx, err); f != nil {
			return PullResponse{OK: false, Failure: f}, nil
		}
		return PullResponse{}, err
	}
	if werr := resp.Wait(pctx); werr != nil {
		_ = resp.Close()
		if f := classifyPull(pctx, werr); f != nil {
			return PullResponse{OK: false, Failure: f}, nil
		}
		return PullResponse{}, werr
	}
	_ = resp.Close()

	// Tag the pulled image as acornfox/<app>:<id> so it is owned by this app.
	if _, err := d.cli.ImageTag(ctx, client.ImageTagOptions{Source: ref, Target: tag}); err != nil {
		return PullResponse{}, err
	}

	info, err := d.inspectByTag(ctx, app, tag)
	if err != nil {
		if cerrdefs.IsNotFound(err) {
			return PullResponse{OK: false, Failure: &Failure{
				Stage: "image", Code: "pull_failed",
				Message: "拉取结束但镜像不可用",
				Hint:    "检查镜像引用后重试",
			}}, nil
		}
		return PullResponse{}, err
	}
	return PullResponse{OK: true, Image: &info}, nil
}

// pullImageTimeout bounds a single image pull (contract: 10 minutes).
const pullImageTimeout = 10 * time.Minute

// pullNotFoundPattern matches "image not found / access denied" pull errors.
// Registry mirrors (e.g. DaoCloud) answer 403 for images they do not carry, so
// 403/404 from a registry count as "not found or not available".
var pullNotFoundPattern = regexp.MustCompile(`(?i)(manifest unknown|manifest for .* not found|not found|no such image|repository does not exist|pull access denied|unauthorized|access to the resource is denied|403 forbidden|404 not found)`)

// classifyPull turns a pull error into a user-facing Failure, or nil when the
// error is a daemon/transport problem the caller should surface as an error.
func classifyPull(ctx context.Context, err error) *Failure {
	if err == nil {
		return nil
	}
	// Timeout: our own deadline elapsed, or the daemon reported a timeout.
	if errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) {
		return &Failure{
			Stage: "image", Code: "pull_timeout",
			Message: "拉取镜像超时",
			Hint:    "国内服务器拉取公共镜像常超时，请为 Docker 配置镜像加速后重试",
		}
	}
	msg := ansiPattern.ReplaceAllString(err.Error(), "")
	if cerrdefs.IsNotFound(err) || cerrdefs.IsUnauthorized(err) || pullNotFoundPattern.MatchString(msg) {
		return &Failure{
			Stage: "image", Code: "image_not_found",
			Message: "找不到镜像，或镜像加速源不提供该镜像：" + msg,
			Hint:    "检查镜像名与标签是否正确；若镜像确实存在，可能是加速源未收录，换用其他加速源或自行构建",
		}
	}
	if pullFailurePattern.MatchString(msg) {
		return &Failure{
			Stage: "image", Code: "pull_timeout",
			Message: "拉取镜像网络异常：" + msg,
			Hint:    "为 Docker 配置镜像加速后重试",
		}
	}
	// Any other daemon-reported pull error is a user-visible pull_failed.
	return &Failure{
		Stage: "image", Code: "pull_failed",
		Message: "拉取镜像失败：" + msg,
		Hint:    "检查镜像引用或稍后重试",
	}
}

// inspectByTag inspects the image carrying tag and confirms tag ownership: a
// pulled image has no acornfox labels, so ownership is established by the
// acornfox/<app>:<id> tag itself. It returns cerrdefs.ErrNotFound when the tag
// is absent or the image does not carry it.
func (d *Docker) inspectByTag(ctx context.Context, app, tag string) (ImageInfo, error) {
	res, err := d.cli.ImageInspect(ctx, tag)
	if err != nil {
		return ImageInfo{}, err
	}
	if !hasTag(res.RepoTags, tag) {
		return ImageInfo{}, cerrdefs.ErrNotFound
	}
	info := imageInfoFromInspect(res)
	// Pulled images have no acornfox labels; derive app/deployment from the tag.
	info.App = app
	if _, id, ok := parseAppTag(tag); ok {
		info.DeploymentID = id
	}
	return info, nil
}

// hasTag reports whether tag is present in tags.
func hasTag(tags []string, tag string) bool {
	for _, t := range tags {
		if t == tag {
			return true
		}
	}
	return false
}

// appTagPattern matches acornfox/<app>:<deployment-id> tags.
var appTagPattern = regexp.MustCompile(`^acornfox/([a-z][a-z0-9-]{0,38}[a-z0-9]):([0-9a-f]{12})$`)

// parseAppTag extracts (app, deploymentID) from an acornfox/<app>:<id> tag.
func parseAppTag(tag string) (app, deploymentID string, ok bool) {
	m := appTagPattern.FindStringSubmatch(tag)
	if m == nil {
		return "", "", false
	}
	return m[1], m[2], true
}

// ownsByTag reports whether any RepoTag is an acornfox/<app>: tag for app,
// establishing ownership of images we pulled (which carry no labels).
func ownsByTag(tags []string, app string) (deploymentID string, ok bool) {
	for _, t := range tags {
		if a, id, matched := parseAppTag(t); matched && a == app {
			return id, true
		}
	}
	return "", false
}

// inspectImage inspects ref and verifies it is a managed image of app.
// Ownership holds when the image carries our labels (built images) or an
// acornfox/<app>: RepoTag (pulled images have no labels, only the tag).
func (d *Docker) inspectImage(ctx context.Context, ref, app string) (ImageInfo, error) {
	res, err := d.cli.ImageInspect(ctx, ref)
	if err != nil {
		return ImageInfo{}, err
	}
	info := imageInfoFromInspect(res)
	if info.App == app {
		return info, nil
	}
	// Pulled images have no labels: fall back to tag ownership.
	if id, ok := ownsByTag(res.RepoTags, app); ok {
		info.App = app
		if info.DeploymentID == "" {
			info.DeploymentID = id
		}
		return info, nil
	}
	// Not a managed image of this app: treat as absent.
	return ImageInfo{}, cerrdefs.ErrNotFound
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

// ListImages lists managed images, optionally filtered to one app. It returns
// both label-managed images (built) and images owned only by an
// acornfox/<app>: RepoTag (pulled).
func (d *Docker) ListImages(ctx context.Context, app string) ([]ImageInfo, error) {
	seen := map[string]ImageInfo{}

	// Label-managed images (built by us).
	labelFilters := client.Filters{}.Add("label", LabelManaged+"=1")
	if app != "" {
		labelFilters = labelFilters.Add("label", LabelApp+"="+app)
	}
	res, err := d.cli.ImageList(ctx, client.ImageListOptions{Filters: labelFilters})
	if err != nil {
		return nil, err
	}
	for _, summary := range res.Items {
		if summary.Labels[LabelManaged] != "1" {
			continue
		}
		info, err := d.inspectImage(ctx, summary.ID, summary.Labels[LabelApp])
		if err != nil {
			continue
		}
		seen[info.ID] = info
	}

	// Tag-owned images (pulled, no labels): match acornfox/<app> references.
	ref := "acornfox/"
	if app != "" {
		ref = "acornfox/" + app
	}
	refFilters := client.Filters{}.Add("reference", ref+"*")
	tagged, err := d.cli.ImageList(ctx, client.ImageListOptions{Filters: refFilters})
	if err != nil {
		return nil, err
	}
	for _, summary := range tagged.Items {
		id, owner, ok := ownerFromTags(summary.RepoTags, app)
		if !ok {
			continue
		}
		if _, dup := seen[summary.ID]; dup {
			continue
		}
		info, err := d.inspectImage(ctx, summary.ID, owner)
		if err != nil {
			continue
		}
		info.DeploymentID = id
		seen[summary.ID] = info
	}

	out := make([]ImageInfo, 0, len(seen))
	for _, info := range seen {
		out = append(out, info)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Created > out[j].Created })
	return out, nil
}

// ownerFromTags finds the acornfox app owning any of tags. When app is "" it
// accepts any acornfox app; otherwise it requires a match.
func ownerFromTags(tags []string, app string) (deploymentID, owner string, ok bool) {
	for _, t := range tags {
		a, id, matched := parseAppTag(t)
		if !matched {
			continue
		}
		if app == "" || a == app {
			return id, a, true
		}
	}
	return "", "", false
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

	role := req.Role
	if role == "" {
		role = RoleApp
	}
	var addon *AddonSpec
	switch role {
	case RoleApp:
	case RoleAddon:
		// Re-checked here (not only at the socket) so no caller of Docker can
		// run anything but the pinned add-on spec under the add-on role.
		spec, err := validateAddonRequest(req)
		if err != nil {
			return ContainerInfo{}, err
		}
		addon = &spec
	default:
		return ContainerInfo{}, fmt.Errorf("invalid role %q", req.Role)
	}

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
		LabelRole:       role,
	}
	pids := int64(DefaultPidsLimit)
	memory := int64(req.MemoryMB) * (1 << 20)
	nanoCPUs := int64(req.CPUMilli) * 1e6

	cfg := &container.Config{
		Image:        req.Image,
		Labels:       labels,
		Env:          envSlice(req.Env),
		ExposedPorts: network.PortSet{containerPort: {}},
	}
	// App containers publish only on loopback; Caddy is the public entry point.
	// Add-ons publish nothing: they are reachable only by name inside
	// NetworkName(app).
	var bindings network.PortMap
	if addon == nil {
		bindings = network.PortMap{containerPort: {{
			HostIP:   netip.MustParseAddr("127.0.0.1"),
			HostPort: "0",
		}}}
	} else {
		if err := d.ensureAddonImage(ctx, addon.Image); err != nil {
			return ContainerInfo{}, err
		}
		if addon.Entrypoint != nil {
			cfg.Entrypoint = addon.Entrypoint
		}
		if hc := addon.Health; hc != nil {
			cfg.Healthcheck = &container.HealthConfig{
				Test:        hc.Test,
				Interval:    hc.Interval,
				Timeout:     hc.Timeout,
				StartPeriod: hc.StartPeriod,
				Retries:     hc.Retries,
			}
		}
	}

	created, err := d.cli.ContainerCreate(ctx, client.ContainerCreateOptions{
		Name:   name,
		Config: cfg,
		HostConfig: &container.HostConfig{
			NetworkMode:   container.NetworkMode(NetworkName(req.App)),
			PortBindings:  bindings,
			RestartPolicy: container.RestartPolicy{Name: container.RestartPolicyUnlessStopped},
			SecurityOpt:   []string{"no-new-privileges"},
			LogConfig: container.LogConfig{
				Type:   "json-file",
				Config: map[string]string{"max-size": LogMaxSize, "max-file": LogMaxFiles},
			},
			Resources: container.Resources{
				Memory:     memory,
				MemorySwap: memory, // equal to Memory: no swap, so the limit is real and OOM is detectable
				NanoCPUs:   nanoCPUs,
				PidsLimit:  &pids,
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

// ensureAddonImage pulls a pinned add-on image if it is not present locally.
// The image is left untagged by AcornFox, so per-app image GC never removes it.
func (d *Docker) ensureAddonImage(ctx context.Context, ref string) error {
	if _, err := d.cli.ImageInspect(ctx, ref); err == nil {
		return nil
	} else if !cerrdefs.IsNotFound(err) {
		return err
	}
	pctx, cancel := context.WithTimeout(ctx, pullImageTimeout)
	defer cancel()
	resp, err := d.cli.ImagePull(pctx, ref, client.ImagePullOptions{})
	if err != nil {
		return fmt.Errorf("%w: %s: %v", ErrPullFailed, ref, err)
	}
	werr := resp.Wait(pctx)
	_ = resp.Close()
	if werr != nil {
		return fmt.Errorf("%w: %s: %v", ErrPullFailed, ref, werr)
	}
	return nil
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
	if res, err := d.cli.NetworkInspect(ctx, name, client.NetworkInspectOptions{}); err == nil {
		return checkNetworkOwner(app, res.Network)
	} else if !cerrdefs.IsNotFound(err) {
		return err
	}
	_, err := d.cli.NetworkCreate(ctx, name, client.NetworkCreateOptions{
		Driver: "bridge",
		Labels: map[string]string{LabelManaged: "1", LabelApp: app},
	})
	// A concurrent creator may have claimed the name; re-check ownership.
	if err != nil && cerrdefs.IsConflict(err) {
		res, inspectErr := d.cli.NetworkInspect(ctx, name, client.NetworkInspectOptions{})
		if inspectErr != nil {
			return inspectErr
		}
		return checkNetworkOwner(app, res.Network)
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
		if c.State.Health != nil && c.State.Health.Status != container.NoHealthcheck {
			info.Health = string(c.State.Health.Status)
		}
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
	c, err := d.managedContainer(ctx, app, name)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	_, err = d.cli.ContainerStop(ctx, c.ID, client.ContainerStopOptions{})
	if cerrdefs.IsNotFound(err) {
		return nil
	}
	return err
}

// StartContainer starts only a labeled container of app.
func (d *Docker) StartContainer(ctx context.Context, app, name string) (ContainerInfo, error) {
	c, err := d.managedContainer(ctx, app, name)
	if err != nil {
		return ContainerInfo{}, err
	}
	if err := d.startByName(ctx, c.ID); err != nil {
		if cerrdefs.IsNotFound(err) {
			return ContainerInfo{}, ErrNotFound
		}
		return ContainerInfo{}, err
	}
	return d.containerInfoByID(ctx, c.ID)
}

// RemoveContainer force-removes only a labeled container of app. Missing is success.
func (d *Docker) RemoveContainer(ctx context.Context, app, name string) error {
	c, err := d.managedContainer(ctx, app, name)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	_, err = d.cli.ContainerRemove(ctx, c.ID, client.ContainerRemoveOptions{Force: true})
	if cerrdefs.IsNotFound(err) {
		return nil
	}
	return err
}

// Logs preserves the existing line-only API, using the timestamped reader.
func (d *Docker) Logs(ctx context.Context, app, name string, tail int) ([]string, error) {
	batch, err := d.LogBatch(ctx, app, name, tail, "")
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(batch.Records))
	for _, record := range batch.Records {
		out = append(out, record.Text)
	}
	return out, nil
}

// ContainerStats never queries unowned or stopped containers.
func (d *Docker) ContainerStats(ctx context.Context, app, name string) (StatsResponse, error) {
	c, err := d.managedContainer(ctx, app, name)
	if err != nil {
		return StatsResponse{}, err
	}
	if c.State == nil || !c.State.Running {
		return StatsResponse{}, ErrStopped
	}
	stats, err := d.cli.ContainerStats(ctx, c.ID, client.ContainerStatsOptions{Stream: false, IncludePreviousSample: true})
	if err != nil {
		if cerrdefs.IsNotFound(err) {
			return StatsResponse{}, ErrNotFound
		}
		return StatsResponse{}, err
	}
	defer stats.Body.Close()
	var v container.StatsResponse
	if err := json.NewDecoder(stats.Body).Decode(&v); err != nil {
		return StatsResponse{}, err
	}
	return containerStatsView(v), nil
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
	owned, err := d.managedContainer(ctx, app, name)
	if err != nil {
		return nil, err
	}
	var mountTargets []string
	for _, mp := range owned.Mounts {
		if mp.Destination != "" {
			mountTargets = append(mountTargets, path.Clean(mp.Destination))
		}
	}

	res, err := d.cli.ContainerDiff(ctx, owned.ID, client.ContainerDiffOptions{})
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

// RemoveVolume deletes a named volume that is managed and labeled for app.
// A missing volume is success. A volume still attached to a container is an
// error (it is never force-removed). The label check matters because volume
// name prefixes alone can overlap between apps ("af-a-" vs "af-a-b-").
func (d *Docker) RemoveVolume(ctx context.Context, app, name string) error {
	if !strings.HasPrefix(name, VolumePrefix(app)) {
		return fmt.Errorf("volume %q must start with %q", name, VolumePrefix(app))
	}
	res, err := d.cli.VolumeInspect(ctx, name, client.VolumeInspectOptions{})
	if err != nil {
		if cerrdefs.IsNotFound(err) {
			return nil
		}
		return err
	}
	if res.Volume.Labels[LabelManaged] != "1" || res.Volume.Labels[LabelApp] != app {
		return fmt.Errorf("volume %q is not managed for app %q", name, app)
	}
	if _, err := d.cli.VolumeRemove(ctx, name, client.VolumeRemoveOptions{}); err != nil {
		if cerrdefs.IsNotFound(err) {
			return nil
		}
		return err
	}
	return nil
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
