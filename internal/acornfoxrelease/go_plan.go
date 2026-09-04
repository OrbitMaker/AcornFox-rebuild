package acornfoxrelease

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

var ErrGoPlan = errors.New("acornfox go build plan is invalid")

const maxGoListBytes = 64 << 20

const maxGoPlanObservation = 30 * time.Second

type GoBuildTargetV1 struct {
	Name    string
	Package string
	Output  string
	Ldflags []string
}

// GoBuildPlanV1 is an immutable description of a build that a later assembly
// step may perform. Preparing it only inspects Git and the local Go cache.
type GoBuildPlanV1 struct {
	valid              bool
	decisionSHA256     string
	sourcePolicySHA256 string
	toolchainSHA256    string
	module             string
	sourceCommit       string
	baseFlags          []string
	environment        []string
	packages           []string
	targets            []GoBuildTargetV1
}

var fixedTargets = []struct{ name, path, identity string }{
	{"acornfox-server", "./cmd/open-card-server", "acornfox"},
	{"acornfox-agent", "./cmd/open-card-agent", "acornfox"},
	{"acornfox-static-server", "./cmd/open-card-static-server", ""},
	{"acornfox-secretctl", "./cmd/open-card-secretctl", ""},
	{"acornfox-security-probe", "./cmd/open-card-security-probe", ""},
	{"acornfox-imagegc", "./cmd/open-card-imagegc", ""},
	{"acornfox", "./cmd/acornfox", ""},
	{"acornfox-admin", "./cmd/open-card-admin", ""},
	{"acornfox-upgrade", "./cmd/open-card-upgrade", "acornfox"},
	{"acornfox-healthcheck", "./cmd/open-card-healthcheck", "acornfox"},
}

type goCommandRunner func(context.Context, string, []string, string, []string) ([]byte, error)

// PrepareGoBuildPlanV1 makes exactly one offline `go list` observation. It
// never invokes `go build`, accepts no caller build flags, and rechecks the
// pinned Git source after Go has inspected it.
func PrepareGoBuildPlanV1(ctx context.Context, witness Witness, policy SourcePolicyV1, toolchain ToolchainInputsV1, root, taskCacheRoot string) (GoBuildPlanV1, error) {
	return prepareGoBuildPlanV1(ctx, witness, policy, toolchain, root, taskCacheRoot, localGoCommand)
}

func prepareGoBuildPlanV1(ctx context.Context, witness Witness, policy SourcePolicyV1, toolchain ToolchainInputsV1, root, taskCacheRoot string, run goCommandRunner) (GoBuildPlanV1, error) {
	if ctx == nil || ctx.Err() != nil || run == nil || !witness.Valid() {
		return GoBuildPlanV1{}, ErrGoPlan
	}
	ctx, cancel := context.WithTimeout(ctx, maxGoPlanObservation)
	defer cancel()
	sourceRaw, sourceErr := CanonicalSourcePolicyV1(policy)
	toolchainRaw, toolchainErr := CanonicalToolchainInputsV1(toolchain)
	decisionSHA, decisionErr := witness.SHA256()
	if sourceErr != nil || toolchainErr != nil || decisionErr != nil || sha256Text(sourceRaw) != witness.decision.SourcePolicySHA256 || sha256Text(toolchainRaw) != witness.decision.ToolchainSHA256 || policy.ModulePath != modulePathForRepository(witness.decision.SourceRepository) {
		return GoBuildPlanV1{}, ErrGoPlan
	}
	if err := VerifyGitSourceV1(ctx, root, witness, policy); err != nil {
		return GoBuildPlanV1{}, ErrGoPlan
	}
	root, cacheRoot, env, err := sealedGoEnvironment(root, taskCacheRoot)
	if err != nil {
		return GoBuildPlanV1{}, ErrGoPlan
	}
	version, err := run(ctx, "go", []string{"version"}, root, env)
	if err != nil || goVersionFromOutput(version) != toolchain.GoVersion {
		return GoBuildPlanV1{}, ErrGoPlan
	}
	packages := fixedPackagePaths(policy.ModulePath)
	listArgs := append([]string{"list", "-mod=readonly", "-buildvcs=false", "-deps", "-json"}, packages...)
	listRaw, err := run(ctx, "go", listArgs, root, env)
	if err != nil || len(listRaw) == 0 || len(listRaw) > maxGoListBytes || !verifyGoListClosure(listRaw, policy, root, cacheRoot) {
		return GoBuildPlanV1{}, ErrGoPlan
	}
	if err := VerifyGitSourceV1(ctx, root, witness, policy); err != nil {
		return GoBuildPlanV1{}, ErrGoPlan
	}
	targets := sealedTargets(witness)
	return GoBuildPlanV1{
		valid:              true,
		decisionSHA256:     decisionSHA,
		sourcePolicySHA256: sha256Text(sourceRaw),
		toolchainSHA256:    sha256Text(toolchainRaw),
		module:             policy.ModulePath,
		sourceCommit:       witness.decision.SourceCommit,
		baseFlags:          GoBaseFlags(),
		environment:        append([]string(nil), env...),
		packages:           append([]string(nil), packages...),
		targets:            targets,
	}, nil
}

func localGoCommand(ctx context.Context, name string, args []string, dir string, env []string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	cmd.Env = append([]string(nil), env...)
	var stdout cappedBuffer
	stdout.limit = maxGoListBytes
	cmd.Stdout = &stdout
	// Command diagnostics may contain source paths; they are intentionally not
	// retained in release evidence. A non-zero exit is enough to fail closed.
	cmd.Stderr = io.Discard
	err := cmd.Run()
	if stdout.exceeded || err != nil {
		return nil, ErrGoPlan
	}
	return stdout.Bytes(), nil
}

type cappedBuffer struct {
	bytes.Buffer
	limit    int
	exceeded bool
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	if b.exceeded || len(p) > b.limit-b.Len() {
		b.exceeded = true
		return len(p), nil
	}
	return b.Buffer.Write(p)
}

func sealedGoEnvironment(root, taskCacheRoot string) (string, string, []string, error) {
	root, err := cleanExistingDirectory(root)
	if err != nil {
		return "", "", nil, err
	}
	if !filepath.IsAbs(taskCacheRoot) || filepath.Clean(taskCacheRoot) == root {
		return "", "", nil, ErrGoPlan
	}
	if err := os.MkdirAll(taskCacheRoot, 0o700); err != nil {
		return "", "", nil, err
	}
	cacheRoot, err := cleanExistingDirectory(taskCacheRoot)
	if err != nil || pathWithin(root, cacheRoot) {
		return "", "", nil, ErrGoPlan
	}
	goCache := filepath.Join(cacheRoot, "go-cache")
	modCache := filepath.Join(cacheRoot, "go-mod-cache")
	for _, path := range []string{goCache, modCache} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			return "", "", nil, err
		}
		if _, err := cleanExistingDirectory(path); err != nil {
			return "", "", nil, ErrGoPlan
		}
	}
	env := []string{
		"PATH=" + os.Getenv("PATH"), "LANG=" + os.Getenv("LANG"), "TMPDIR=" + os.Getenv("TMPDIR"),
		"GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0", "GOWORK=off", "GOENV=off", "GOTOOLCHAIN=local", "GOPROXY=off", "GOVCS=*:off",
		"GOCACHE=" + goCache, "GOMODCACHE=" + modCache,
		"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_TERMINAL_PROMPT=0",
	}
	return root, cacheRoot, env, nil
}

func cleanExistingDirectory(path string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", ErrGoPlan
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", ErrGoPlan
	}
	clean, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", ErrGoPlan
	}
	return filepath.Clean(clean), nil
}

func fixedPackagePaths(module string) []string {
	out := make([]string, 0, len(fixedTargets))
	for _, target := range fixedTargets {
		out = append(out, module+"/"+strings.TrimPrefix(target.path, "./"))
	}
	return out
}

func goVersionFromOutput(raw []byte) string {
	fields := strings.Fields(string(raw))
	if len(fields) != 4 || fields[0] != "go" || fields[1] != "version" || !goVersionText.MatchString(fields[2]) {
		return ""
	}
	return fields[2]
}

type goListPackage struct {
	ImportPath string        `json:"ImportPath"`
	Dir        string        `json:"Dir"`
	Standard   bool          `json:"Standard"`
	Incomplete bool          `json:"Incomplete"`
	Error      *goListError  `json:"Error"`
	Module     *goListModule `json:"Module"`
}
type goListError struct {
	Err string `json:"Err"`
}
type goListModule struct {
	Path    string        `json:"Path"`
	Version string        `json:"Version"`
	Main    bool          `json:"Main"`
	Dir     string        `json:"Dir"`
	Replace *goListModule `json:"Replace"`
}

func verifyGoListClosure(raw []byte, policy SourcePolicyV1, root, cacheRoot string) bool {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	mainImports := make(map[string]bool)
	seenPackage := false
	for {
		var pkg goListPackage
		err := decoder.Decode(&pkg)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil || pkg.ImportPath == "" || pkg.Incomplete || pkg.Error != nil || (pkg.Standard && pkg.Module != nil) {
			return false
		}
		seenPackage = true
		if pkg.Standard {
			continue
		}
		if pkg.Module == nil || pkg.Module.Path == "" || pkg.Module.Replace != nil {
			return false
		}
		if pkg.Module.Main {
			if pkg.Module.Path != policy.ModulePath || !pathWithin(root, pkg.Dir) || !pathWithin(root, pkg.Module.Dir) || mainImports[pkg.ImportPath] {
				return false
			}
			mainImports[pkg.ImportPath] = true
			continue
		}
		if pkg.Module.Version == "" || strings.HasPrefix(pkg.ImportPath, policy.ModulePath+"/") || pkg.ImportPath == policy.ModulePath || !cachedModuleDirectory(cacheRoot, pkg.Dir) || !cachedModuleDirectory(cacheRoot, pkg.Module.Dir) {
			return false
		}
	}
	if !seenPackage || len(mainImports) != len(policy.GoPackages) {
		return false
	}
	for _, importPath := range policy.GoPackages {
		if !mainImports[importPath] {
			return false
		}
	}
	return true
}

func pathWithin(root, path string) bool {
	if root == "" || path == "" || !filepath.IsAbs(root) || !filepath.IsAbs(path) {
		return false
	}
	rel, err := filepath.Rel(root, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func cachedModuleDirectory(cacheRoot, path string) bool {
	cacheRoot, err := cleanExistingDirectory(cacheRoot)
	if err != nil {
		return false
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return false
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || filepath.Clean(resolved) == cacheRoot {
		return false
	}
	return pathWithin(cacheRoot, filepath.Clean(resolved))
}

func sealedTargets(witness Witness) []GoBuildTargetV1 {
	targets := make([]GoBuildTargetV1, 0, len(fixedTargets))
	for _, target := range fixedTargets {
		flags := []string{"-buildid="}
		if target.identity != "" {
			flags = append(flags, "-X=main.processIdentity=acornfox")
		}
		if target.name == "acornfox-upgrade" || target.name == "acornfox-healthcheck" {
			flags = append(flags, "-X=main.buildVersion="+witness.decision.Version, "-X=main.buildSourceCommit="+witness.decision.SourceCommit, "-X=main.buildLayoutSchema=1")
		}
		targets = append(targets, GoBuildTargetV1{Name: target.name, Package: target.path, Output: "bin/" + target.name, Ldflags: flags})
	}
	return targets
}

func (p GoBuildPlanV1) Valid() bool {
	return p.valid && len(p.targets) == len(fixedTargets) && len(p.packages) == len(fixedTargets) && p.decisionSHA256 != "" && p.sourcePolicySHA256 != "" && p.toolchainSHA256 != "" && p.module != "" && p.sourceCommit != ""
}
func (p GoBuildPlanV1) Targets() []GoBuildTargetV1 { return copyTargets(p.targets, p.Valid()) }
func (p GoBuildPlanV1) Packages() []string {
	if !p.Valid() {
		return nil
	}
	return append([]string(nil), p.packages...)
}
func (p GoBuildPlanV1) BaseFlags() []string {
	if !p.Valid() {
		return nil
	}
	return append([]string(nil), p.baseFlags...)
}
func (p GoBuildPlanV1) Environment() []string {
	if !p.Valid() {
		return nil
	}
	return append([]string(nil), p.environment...)
}
func (p GoBuildPlanV1) DecisionSHA256() string     { return sealedPlanValue(p, p.decisionSHA256) }
func (p GoBuildPlanV1) SourcePolicySHA256() string { return sealedPlanValue(p, p.sourcePolicySHA256) }
func (p GoBuildPlanV1) ToolchainSHA256() string    { return sealedPlanValue(p, p.toolchainSHA256) }
func (p GoBuildPlanV1) Module() string             { return sealedPlanValue(p, p.module) }
func (p GoBuildPlanV1) SourceCommit() string       { return sealedPlanValue(p, p.sourceCommit) }
func sealedPlanValue(p GoBuildPlanV1, value string) string {
	if !p.Valid() {
		return ""
	}
	return value
}
func copyTargets(targets []GoBuildTargetV1, valid bool) []GoBuildTargetV1 {
	if !valid {
		return nil
	}
	out := make([]GoBuildTargetV1, len(targets))
	for i, target := range targets {
		out[i] = target
		out[i].Ldflags = append([]string(nil), target.Ldflags...)
	}
	return out
}
func GoBaseFlags() []string { return []string{"-trimpath", "-buildvcs=false"} }
