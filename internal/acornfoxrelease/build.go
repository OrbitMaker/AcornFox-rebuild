package acornfoxrelease

import (
	"context"
	"crypto/sha256"
	"debug/buildinfo"
	"debug/elf"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
)

var ErrGoStage = errors.New("acornfox go binary stage is invalid")

const maxGoBinaryOutputBytes int64 = 128 << 20

// GoBinaryReceiptV1 describes synthetic binaries held by a private stage. It
// is not a release manifest and cannot name a final candidate location.
type GoBinaryReceiptV1 struct {
	SchemaVersion      int           `json:"schema_version"`
	Product            string        `json:"product"`
	Architecture       string        `json:"architecture"`
	SourceCommit       string        `json:"source_commit"`
	DecisionSHA256     string        `json:"decision_sha256"`
	SourcePolicySHA256 string        `json:"source_policy_sha256"`
	ToolchainSHA256    string        `json:"toolchain_sha256"`
	TreeSHA256         string        `json:"tree_sha256"`
	Files              []FileEntryV1 `json:"files"`
}

func (r GoBinaryReceiptV1) Validate() error {
	if r.SchemaVersion != 1 || r.Product != Product || r.Architecture != Architecture || !commitText.MatchString(r.SourceCommit) || !digestText.MatchString(r.DecisionSHA256) || !digestText.MatchString(r.SourcePolicySHA256) || !digestText.MatchString(r.ToolchainSHA256) || !digestText.MatchString(r.TreeSHA256) || validateEntries(r.Files) != nil || len(r.Files) != len(fixedTargets) {
		return ErrGoStage
	}
	want := map[string]bool{}
	for _, target := range fixedTargets {
		want["bin/"+target.name] = true
	}
	for _, file := range r.Files {
		if file.Mode != 0o755 || !want[file.Path] {
			return ErrGoStage
		}
		delete(want, file.Path)
	}
	tree, err := canonicalBinaryTree(r.Files)
	if err != nil || sha256Text(tree) != r.TreeSHA256 || len(want) != 0 {
		return ErrGoStage
	}
	return nil
}

type GoBinaryStageV1 struct {
	root       string
	parent     string
	parentInfo os.FileInfo
	stageInfo  os.FileInfo
	receipt    GoBinaryReceiptV1
	closed     bool
}

func BuildGoBinariesV1(ctx context.Context, plan GoBuildPlanV1, taskRoot string) (*GoBinaryStageV1, error) {
	return buildGoBinariesV1(ctx, plan, taskRoot, plan.goExecutable.run, nil)
}

func buildGoBinariesV1(ctx context.Context, plan GoBuildPlanV1, taskRoot string, runner goCommandRunner, outputHook func(string) error) (*GoBinaryStageV1, error) {
	if ctx == nil || ctx.Err() != nil || !plan.Valid() || runner == nil || VerifySourceTree(plan.sourceRoot, plan.sourcePolicy) != nil {
		return nil, ErrGoStage
	}
	taskRoot, parentInfo, err := pinStageParent(taskRoot)
	if err != nil {
		return nil, ErrGoStage
	}
	stageRoot, err := os.MkdirTemp(taskRoot, ".acornfox-go-stage-")
	if err != nil {
		return nil, ErrGoStage
	}
	stageInfo, err := os.Lstat(stageRoot)
	stage := &GoBinaryStageV1{root: stageRoot, parent: taskRoot, parentInfo: parentInfo, stageInfo: stageInfo}
	if err != nil || os.Chmod(stageRoot, 0o700) != nil {
		return nil, cleanupFailedStage(stage, ErrGoStage)
	}
	fail := func(err error) (*GoBinaryStageV1, error) { return nil, cleanupFailedStage(stage, err) }
	snapshot := filepath.Join(stageRoot, "source")
	if err := os.Mkdir(snapshot, 0o700); err != nil {
		return fail(ErrGoStage)
	}
	if err := copyFrozenSource(plan.sourceRoot, snapshot, plan.sourcePolicy); err != nil {
		return fail(err)
	}
	if VerifySourceTree(plan.sourceRoot, plan.sourcePolicy) != nil || VerifySourceTree(snapshot, plan.sourcePolicy) != nil || !plan.cache.valid() {
		return fail(ErrGoStage)
	}
	stageCache := filepath.Join(stageRoot, "go-cache")
	stageTmp := filepath.Join(stageRoot, "tmp")
	binRoot := filepath.Join(stageRoot, "bin")
	for _, path := range []string{stageCache, stageTmp, binRoot} {
		if err := os.Mkdir(path, 0o700); err != nil {
			return fail(ErrGoStage)
		}
	}
	env, err := buildStageEnvironment(plan.Environment(), stageCache, stageTmp)
	if err != nil {
		return fail(err)
	}
	goExecutable := plan.goExecutable
	goExecutable.run = runner
	if version, err := goExecutable.Run(ctx, []string{"version"}, snapshot, env); err != nil || goVersionFromOutput(version) != plan.toolchain.GoVersion {
		return fail(ErrGoStage)
	}
	if verified, err := goExecutable.Run(ctx, []string{"mod", "verify"}, snapshot, env); err != nil || string(verified) != "all modules verified\n" {
		return fail(ErrGoStage)
	}
	for _, target := range plan.Targets() {
		output := filepath.Join(stageRoot, filepath.FromSlash(target.Output))
		args := []string{"build", "-mod=readonly", "-trimpath", "-buildvcs=false", "-ldflags", strings.Join(target.Ldflags, " "), "-o", output, target.Package}
		if _, err := goExecutable.Run(ctx, args, snapshot, env); err != nil {
			return fail(ErrGoStage)
		}
		if outputHook != nil {
			if err := outputHook(output); err != nil {
				return fail(ErrGoStage)
			}
		}
	}
	if verified, err := goExecutable.Run(ctx, []string{"mod", "verify"}, snapshot, env); err != nil || string(verified) != "all modules verified\n" || !plan.cache.valid() || VerifySourceTree(snapshot, plan.sourcePolicy) != nil || VerifySourceTree(plan.sourceRoot, plan.sourcePolicy) != nil {
		return fail(ErrGoStage)
	}
	files, err := inspectBinaryTree(stageRoot, plan)
	if err != nil {
		return fail(err)
	}
	tree, err := canonicalBinaryTree(files)
	if err != nil {
		return fail(err)
	}
	stage.receipt = GoBinaryReceiptV1{SchemaVersion: 1, Product: Product, Architecture: Architecture, SourceCommit: plan.sourceCommit, DecisionSHA256: plan.decisionSHA256, SourcePolicySHA256: plan.sourcePolicySHA256, ToolchainSHA256: plan.toolchainSHA256, TreeSHA256: sha256Text(tree), Files: files}
	if stage.receipt.Validate() != nil || !stage.valid() {
		return fail(ErrGoStage)
	}
	return stage, nil
}

func (stage *GoBinaryStageV1) Receipt() (GoBinaryReceiptV1, error) {
	if stage == nil || stage.closed || !stage.valid() {
		return GoBinaryReceiptV1{}, ErrGoStage
	}
	copy := stage.receipt
	copy.Files = append([]FileEntryV1(nil), stage.receipt.Files...)
	return copy, nil
}

func (stage *GoBinaryStageV1) Close() error {
	if stage == nil || stage.closed {
		return nil
	}
	if !stage.valid() {
		return ErrGoStage
	}
	if err := os.RemoveAll(stage.root); err != nil {
		return ErrGoStage
	}
	stage.closed = true
	return nil
}

func (stage *GoBinaryStageV1) valid() bool {
	if stage == nil || stage.closed || stage.receipt.Validate() != nil || !samePinnedDirectory(stage.parent, stage.parentInfo) || !samePinnedDirectory(stage.root, stage.stageInfo) {
		return false
	}
	files, err := inspectReceiptTree(stage.root, stage.receipt)
	if err != nil {
		return false
	}
	return sameFileEntries(files, stage.receipt.Files)
}

func cleanupFailedStage(stage *GoBinaryStageV1, err error) error {
	if stage != nil && samePinnedDirectory(stage.parent, stage.parentInfo) && samePinnedDirectory(stage.root, stage.stageInfo) {
		_ = os.RemoveAll(stage.root)
	}
	return ErrGoStage
}

func pinStageParent(root string) (string, os.FileInfo, error) {
	root, err := cleanExistingDirectory(root)
	if err != nil {
		return "", nil, ErrGoStage
	}
	info, err := os.Lstat(root)
	if err != nil || info.Mode().Perm() != 0o700 || linkCount(info) > 2 {
		return "", nil, ErrGoStage
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); !ok || int(stat.Uid) != os.Getuid() {
		return "", nil, ErrGoStage
	}
	return root, info, nil
}

func copyFrozenSource(sourceRoot, destination string, policy SourcePolicyV1) error {
	root, err := os.OpenRoot(sourceRoot)
	if err != nil {
		return ErrGoStage
	}
	defer root.Close()
	for _, entry := range policy.Files {
		before, err := root.Lstat(entry.Path)
		if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Mode().Perm() != os.FileMode(entry.Mode) || linkCount(before) != 1 || before.Size() < 0 || before.Size() > sourceFileBytes {
			return ErrGoStage
		}
		if err := os.MkdirAll(filepath.Dir(filepath.Join(destination, filepath.FromSlash(entry.Path))), 0o700); err != nil {
			return ErrGoStage
		}
		input, err := root.OpenFile(entry.Path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if err != nil {
			return ErrGoStage
		}
		opened, statErr := input.Stat()
		output, createErr := os.OpenFile(filepath.Join(destination, filepath.FromSlash(entry.Path)), os.O_WRONLY|os.O_CREATE|os.O_EXCL, os.FileMode(entry.Mode))
		if createErr != nil {
			input.Close()
			return ErrGoStage
		}
		hash := sha256.New()
		reader := io.TeeReader(io.LimitReader(input, sourceFileBytes+1), hash)
		n, copyErr := io.Copy(output, reader)
		closeOut := output.Close()
		closeIn := input.Close()
		after, afterErr := root.Lstat(entry.Path)
		if statErr != nil || copyErr != nil || closeOut != nil || closeIn != nil || afterErr != nil || n != before.Size() || n > sourceFileBytes || !os.SameFile(before, opened) || !os.SameFile(before, after) || hex.EncodeToString(hash.Sum(nil)) != entry.SHA256 || os.Chmod(filepath.Join(destination, filepath.FromSlash(entry.Path)), os.FileMode(entry.Mode)) != nil {
			return ErrGoStage
		}
	}
	return nil
}

func buildStageEnvironment(base []string, goCache, tmp string) ([]string, error) {
	values := map[string]string{}
	order := make([]string, 0, len(base))
	for _, value := range base {
		key, _, ok := strings.Cut(value, "=")
		if !ok || key == "" || values[key] != "" {
			return nil, ErrGoStage
		}
		values[key] = value
		order = append(order, key)
	}
	values["GOCACHE"] = "GOCACHE=" + goCache
	values["TMPDIR"] = "TMPDIR=" + tmp
	for _, required := range []string{"GOMODCACHE", "GOPROXY=off", "GOSUMDB=off", "GOVCS=*:off", "GOTOOLCHAIN=local", "GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0"} {
		key, value, hasValue := strings.Cut(required, "=")
		if !hasValue {
			if values[key] == "" {
				return nil, ErrGoStage
			}
			continue
		}
		if values[key] != key+"="+value {
			return nil, ErrGoStage
		}
	}
	out := make([]string, 0, len(order))
	for _, key := range order {
		out = append(out, values[key])
	}
	return out, nil
}

func inspectBinaryTree(stageRoot string, plan GoBuildPlanV1) ([]FileEntryV1, error) {
	entries, err := os.ReadDir(filepath.Join(stageRoot, "bin"))
	if err != nil || len(entries) != len(fixedTargets) {
		return nil, ErrGoStage
	}
	files := make([]FileEntryV1, 0, len(entries))
	for _, target := range plan.Targets() {
		path := filepath.Join(stageRoot, filepath.FromSlash(target.Output))
		entry, err := inspectOneBinary(path, target, plan)
		if err != nil {
			return nil, err
		}
		files = append(files, entry)
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return files, nil
}

func inspectReceiptTree(stageRoot string, receipt GoBinaryReceiptV1) ([]FileEntryV1, error) {
	if receipt.Validate() != nil {
		return nil, ErrGoStage
	}
	entries, err := os.ReadDir(filepath.Join(stageRoot, "bin"))
	if err != nil || len(entries) != len(receipt.Files) {
		return nil, ErrGoStage
	}
	files := make([]FileEntryV1, 0, len(receipt.Files))
	for _, expected := range receipt.Files {
		path := filepath.Join(stageRoot, filepath.FromSlash(expected.Path))
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o755 || linkCount(info) != 1 || info.Size() <= 0 || info.Size() > maxGoBinaryOutputBytes {
			return nil, ErrGoStage
		}
		body, err := os.ReadFile(path)
		if err != nil || sha256Text(body) != expected.SHA256 {
			return nil, ErrGoStage
		}
		files = append(files, FileEntryV1{Path: expected.Path, SHA256: expected.SHA256, Mode: 0o755})
	}
	return files, nil
}

func inspectOneBinary(path string, target GoBuildTargetV1, plan GoBuildPlanV1) (FileEntryV1, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || linkCount(info) != 1 || info.Size() <= 0 || info.Size() > maxGoBinaryOutputBytes {
		return FileEntryV1{}, ErrGoStage
	}
	if err := os.Chmod(path, 0o755); err != nil {
		return FileEntryV1{}, ErrGoStage
	}
	info, err = os.Lstat(path)
	if err != nil || info.Mode().Perm() != 0o755 {
		return FileEntryV1{}, ErrGoStage
	}
	elfFile, err := elf.Open(path)
	if err != nil || elfFile.Class != elf.ELFCLASS64 || elfFile.Data != elf.ELFDATA2LSB || elfFile.Machine != elf.EM_X86_64 {
		if elfFile != nil {
			elfFile.Close()
		}
		return FileEntryV1{}, ErrGoStage
	}
	if err := elfFile.Close(); err != nil {
		return FileEntryV1{}, ErrGoStage
	}
	build, err := buildinfo.ReadFile(path)
	if err != nil || build.Main.Path != plan.module || build.GoVersion != plan.toolchain.GoVersion || !buildSettingsMatch(build, plan, target) {
		return FileEntryV1{}, ErrGoStage
	}
	body, err := os.ReadFile(path)
	if err != nil || !ldflagsPresent(body, target.Ldflags) {
		return FileEntryV1{}, ErrGoStage
	}
	return FileEntryV1{Path: target.Output, SHA256: sha256Text(body), Mode: 0o755}, nil
}

func buildSettingsMatch(build *buildinfo.BuildInfo, plan GoBuildPlanV1, target GoBuildTargetV1) bool {
	settings := map[string]string{}
	for _, setting := range build.Settings {
		settings[setting.Key] = setting.Value
	}
	if settings["GOOS"] != "linux" || settings["GOARCH"] != "amd64" || settings["CGO_ENABLED"] != "0" || settings["-trimpath"] != "true" {
		return false
	}
	for _, key := range []string{"vcs.revision", "vcs.modified", "vcs.time"} {
		if settings[key] != "" {
			return false
		}
	}
	return target.Package != "" && plan.module != ""
}

func ldflagsPresent(binary []byte, flags []string) bool {
	for _, flag := range flags {
		if strings.HasPrefix(flag, "-X=main.") {
			_, value, ok := strings.Cut(flag, "=")
			if !ok {
				return false
			}
			_, value, ok = strings.Cut(value, "=")
			if !ok || !strings.Contains(string(binary), value) {
				return false
			}
		}
	}
	return true
}

func canonicalBinaryTree(files []FileEntryV1) ([]byte, error) {
	if validateEntries(files) != nil {
		return nil, ErrGoStage
	}
	return json.Marshal(files)
}

func sameFileEntries(left, right []FileEntryV1) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func stagePath(stage *GoBinaryStageV1) string {
	if stage == nil {
		return ""
	}
	return stage.root
}
