package acornfoxrelease

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

var ErrGoPlan = errors.New("acornfox go build plan is invalid")

const (
	maxGoListBytes       = 64 << 20
	maxGoBinaryBytes     = 1 << 30
	maxGoPlanObservation = 30 * time.Second
)

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
	sourceRoot         string
	sourcePolicy       SourcePolicyV1
	toolchain          ToolchainInputsV1
	goExecutable       boundExecutable
	cache              sealedGoCache
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
type executableResolver func(string) (string, error)
type executableHasher func(string) (string, error)

type boundExecutable struct {
	path   string
	digest string
	run    goCommandRunner
	hash   executableHasher
}

func bindExecutable(name, digest string, run goCommandRunner, lookup executableResolver, hash executableHasher) (boundExecutable, error) {
	if !digestText.MatchString(digest) || run == nil || lookup == nil || hash == nil {
		return boundExecutable{}, ErrGoPlan
	}
	path, err := resolveTrustedExecutable(name, lookup)
	if err != nil {
		return boundExecutable{}, ErrGoPlan
	}
	actual, err := hash(path)
	if err != nil || actual != digest {
		return boundExecutable{}, ErrGoPlan
	}
	return boundExecutable{path: path, digest: digest, run: run, hash: hash}, nil
}

func (b boundExecutable) Run(ctx context.Context, args []string, dir string, env []string) ([]byte, error) {
	if b.path == "" || !digestText.MatchString(b.digest) || b.run == nil || b.hash == nil {
		return nil, ErrGoPlan
	}
	before, err := b.hash(b.path)
	if err != nil || before != b.digest {
		return nil, ErrGoPlan
	}
	raw, err := b.run(ctx, b.path, args, dir, env)
	after, hashErr := b.hash(b.path)
	if hashErr != nil || after != b.digest {
		return nil, ErrGoPlan
	}
	if err != nil {
		return nil, err
	}
	return raw, nil
}

// PrepareGoBuildPlanV1 makes exactly one offline `go list` observation. It
// never invokes `go build`, accepts no caller build flags, and rechecks the
// pinned Git source after Go has inspected it.
func PrepareGoBuildPlanV1(ctx context.Context, witness Witness, policy SourcePolicyV1, toolchain ToolchainInputsV1, root, taskCacheRoot string) (GoBuildPlanV1, error) {
	return prepareGoBuildPlanV1(ctx, witness, policy, toolchain, root, taskCacheRoot, localGoCommand)
}

func prepareGoBuildPlanV1(ctx context.Context, witness Witness, policy SourcePolicyV1, toolchain ToolchainInputsV1, root, taskCacheRoot string, run goCommandRunner) (GoBuildPlanV1, error) {
	return prepareGoBuildPlanWithDependencies(ctx, witness, policy, toolchain, root, taskCacheRoot, run, exec.LookPath, hashTrustedExecutable)
}

func prepareGoBuildPlanWithDependencies(ctx context.Context, witness Witness, policy SourcePolicyV1, toolchain ToolchainInputsV1, root, taskCacheRoot string, run goCommandRunner, lookup executableResolver, hash executableHasher) (GoBuildPlanV1, error) {
	if ctx == nil || ctx.Err() != nil || run == nil || lookup == nil || hash == nil || !witness.Valid() {
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
	if err := VerifyGitSourceV1(ctx, root, witness, policy, toolchain); err != nil {
		return GoBuildPlanV1{}, ErrGoPlan
	}
	root, cache, env, err := sealedGoEnvironment(root, taskCacheRoot)
	if err != nil {
		return GoBuildPlanV1{}, ErrGoPlan
	}
	goExecutable, err := bindExecutable("go", toolchain.GoBinarySHA256, run, lookup, hash)
	if err != nil {
		return GoBuildPlanV1{}, ErrGoPlan
	}
	version, err := goExecutable.Run(ctx, []string{"version"}, root, env)
	if err != nil || goVersionFromOutput(version) != toolchain.GoVersion {
		return GoBuildPlanV1{}, ErrGoPlan
	}
	verified, err := goExecutable.Run(ctx, []string{"mod", "verify"}, root, env)
	if err != nil || string(verified) != "all modules verified\n" {
		return GoBuildPlanV1{}, ErrGoPlan
	}
	packages := fixedPackagePaths(policy.ModulePath)
	listArgs := append([]string{"list", "-mod=readonly", "-buildvcs=false", "-deps", "-json"}, packages...)
	listRaw, err := goExecutable.Run(ctx, listArgs, root, env)
	if err != nil || len(listRaw) == 0 || len(listRaw) > maxGoListBytes || !verifyGoListClosure(listRaw, policy, root, cache.modPath) || !cache.valid() {
		return GoBuildPlanV1{}, ErrGoPlan
	}
	verified, err = goExecutable.Run(ctx, []string{"mod", "verify"}, root, env)
	if err != nil || string(verified) != "all modules verified\n" || !cache.valid() {
		return GoBuildPlanV1{}, ErrGoPlan
	}
	if err := VerifyGitSourceV1(ctx, root, witness, policy, toolchain); err != nil {
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
		sourceRoot:         root,
		sourcePolicy:       cloneSourcePolicy(policy),
		toolchain:          cloneToolchain(toolchain),
		goExecutable:       goExecutable,
		cache:              cache,
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

type sealedGoCache struct {
	taskPath string
	goPath   string
	modPath  string
	taskInfo os.FileInfo
	goInfo   os.FileInfo
	modInfo  os.FileInfo
}

func sealedGoEnvironment(root, taskCacheRoot string) (string, sealedGoCache, []string, error) {
	root, err := cleanExistingDirectory(root)
	if err != nil {
		return "", sealedGoCache{}, nil, err
	}
	taskCacheRoot, err = cleanExistingDirectory(taskCacheRoot)
	if err != nil || taskCacheRoot == root || pathWithin(root, taskCacheRoot) {
		return "", sealedGoCache{}, nil, ErrGoPlan
	}
	taskInfo, err := os.Lstat(taskCacheRoot)
	if err != nil {
		return "", sealedGoCache{}, nil, ErrGoPlan
	}
	goCache, goInfo, err := pinnedCacheChild(taskCacheRoot, "go-cache")
	if err != nil {
		return "", sealedGoCache{}, nil, ErrGoPlan
	}
	modCache, modInfo, err := pinnedCacheChild(taskCacheRoot, "go-mod-cache")
	if err != nil {
		return "", sealedGoCache{}, nil, ErrGoPlan
	}
	env := []string{
		"PATH=" + os.Getenv("PATH"), "LANG=" + os.Getenv("LANG"), "TMPDIR=" + os.Getenv("TMPDIR"),
		"GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0", "GOWORK=off", "GOENV=off", "GOTOOLCHAIN=local", "GOPROXY=off", "GOVCS=*:off", "GOSUMDB=off",
		"GOCACHE=" + goCache, "GOMODCACHE=" + modCache,
		"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_TERMINAL_PROMPT=0", "GIT_OPTIONAL_LOCKS=0",
	}
	return root, sealedGoCache{taskPath: taskCacheRoot, goPath: goCache, modPath: modCache, taskInfo: taskInfo, goInfo: goInfo, modInfo: modInfo}, env, nil
}

func (cache sealedGoCache) valid() bool {
	return samePinnedDirectory(cache.taskPath, cache.taskInfo) && samePinnedDirectory(cache.goPath, cache.goInfo) && samePinnedDirectory(cache.modPath, cache.modInfo)
}

func samePinnedDirectory(path string, expected os.FileInfo) bool {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || !os.SameFile(info, expected) {
		return false
	}
	return true
}

func pinnedCacheChild(parent, name string) (string, os.FileInfo, error) {
	if name != "go-cache" && name != "go-mod-cache" {
		return "", nil, ErrGoPlan
	}
	root, err := os.OpenRoot(parent)
	if err != nil {
		return "", nil, ErrGoPlan
	}
	defer root.Close()
	parentInfo, err := root.Stat(".")
	if err != nil {
		return "", nil, ErrGoPlan
	}
	outerInfo, err := os.Stat(parent)
	if err != nil || !os.SameFile(parentInfo, outerInfo) {
		return "", nil, ErrGoPlan
	}
	if err := root.Mkdir(name, 0o700); err != nil && !os.IsExist(err) {
		return "", nil, ErrGoPlan
	}
	entry, err := root.Lstat(name)
	if err != nil || !entry.IsDir() || entry.Mode()&os.ModeSymlink != 0 {
		return "", nil, ErrGoPlan
	}
	child, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return "", nil, ErrGoPlan
	}
	defer child.Close()
	opened, err := child.Stat()
	if err != nil || !opened.IsDir() || !os.SameFile(entry, opened) {
		return "", nil, ErrGoPlan
	}
	return filepath.Join(parent, name), opened, nil
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
	clean = filepath.Clean(clean)
	opened, err := os.OpenRoot(clean)
	if err != nil {
		return "", ErrGoPlan
	}
	defer opened.Close()
	rootInfo, err := opened.Stat(".")
	if err != nil || !os.SameFile(info, rootInfo) {
		return "", ErrGoPlan
	}
	return clean, nil
}

func resolveTrustedExecutable(name string, lookup executableResolver) (string, error) {
	path, err := lookup(name)
	if err != nil || !filepath.IsAbs(path) {
		return "", ErrGoPlan
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", ErrGoPlan
	}
	info, err := os.Lstat(resolved)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return "", ErrGoPlan
	}
	return filepath.Clean(resolved), nil
}

func hashTrustedExecutable(path string) (string, error) {
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Size() < 0 || before.Size() > maxGoBinaryBytes {
		return "", ErrGoPlan
	}
	file, err := os.Open(path)
	if err != nil {
		return "", ErrGoPlan
	}
	opened, err := file.Stat()
	hash := sha256.New()
	n, copyErr := io.Copy(hash, io.LimitReader(file, maxGoBinaryBytes+1))
	closeErr := file.Close()
	after, afterErr := os.Lstat(path)
	if err != nil || copyErr != nil || closeErr != nil || afterErr != nil || n != before.Size() || n > maxGoBinaryBytes || !os.SameFile(before, opened) || !os.SameFile(before, after) {
		return "", ErrGoPlan
	}
	return fmt.Sprintf("%x", hash.Sum(nil)), nil
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
	sourceRaw, sourceErr := CanonicalSourcePolicyV1(p.sourcePolicy)
	toolchainRaw, toolchainErr := CanonicalToolchainInputsV1(p.toolchain)
	return p.valid && len(p.targets) == len(fixedTargets) && len(p.packages) == len(fixedTargets) && p.decisionSHA256 != "" && p.sourcePolicySHA256 != "" && p.toolchainSHA256 != "" && p.module != "" && p.sourceCommit != "" && p.sourceRoot != "" && sourceErr == nil && toolchainErr == nil && sha256Text(sourceRaw) == p.sourcePolicySHA256 && sha256Text(toolchainRaw) == p.toolchainSHA256 && VerifySourceTree(p.sourceRoot, p.sourcePolicy) == nil && p.goExecutable.path != "" && p.goExecutable.digest == p.toolchain.GoBinarySHA256 && p.cache.valid()
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

func cloneSourcePolicy(policy SourcePolicyV1) SourcePolicyV1 {
	copy := policy
	copy.GoPackages = append([]string(nil), policy.GoPackages...)
	copy.Files = append([]FileEntryV1(nil), policy.Files...)
	return copy
}

func cloneToolchain(toolchain ToolchainInputsV1) ToolchainInputsV1 {
	copy := toolchain
	copy.BuildPolicy = append([]string(nil), toolchain.BuildPolicy...)
	return copy
}
