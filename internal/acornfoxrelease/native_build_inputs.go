package acornfoxrelease

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strings"
)

// NativeBuildInputsV1 pins a private clean snapshot and tools, independently of
// the historical migration decision. It does not assert publication or readiness.
type NativeBuildInputsV1 struct {
	SchemaVersion      int    `json:"schema_version"`
	Profile            string `json:"profile"`
	Version            string `json:"version"`
	SourceRepository   string `json:"source_repository"`
	SourceCommit       string `json:"source_commit"`
	SourcePolicySHA256 string `json:"source_policy_sha256"`
	ToolchainSHA256    string `json:"toolchain_sha256"`
}

func (v NativeBuildInputsV1) Validate() error {
	if v.SchemaVersion != 1 || (v.Profile != "native_partial" && v.Profile != "native_product") || !versionText.MatchString(v.Version) || !validGitHubRepository(v.SourceRepository) || !commitText.MatchString(v.SourceCommit) || !digestText.MatchString(v.SourcePolicySHA256) || !digestText.MatchString(v.ToolchainSHA256) {
		return ErrInputs
	}
	return nil
}

func CanonicalNativeBuildInputsV1(v NativeBuildInputsV1) ([]byte, error) {
	if v.Validate() != nil {
		return nil, ErrInputs
	}
	return json.Marshal(v)
}

type NativeBuildWitness struct {
	inputs NativeBuildInputsV1
	sha    string
}

func (w NativeBuildWitness) Profile() string {
	if !w.valid() {
		return ""
	}
	return w.inputs.Profile
}

func ParseNativeBuildInputsV1(raw []byte, expectedSHA string) (NativeBuildWitness, error) {
	var v NativeBuildInputsV1
	if !digestText.MatchString(expectedSHA) || sha256Text(raw) != expectedSHA || parseCanonical(raw, &v) != nil || v.Validate() != nil {
		return NativeBuildWitness{}, ErrInputs
	}
	return NativeBuildWitness{v, expectedSHA}, nil
}
func (w NativeBuildWitness) valid() bool {
	raw, err := CanonicalNativeBuildInputsV1(w.inputs)
	return err == nil && digestText.MatchString(w.sha) && sha256Text(raw) == w.sha
}
func ParseNativeSourcePolicyV1(w NativeBuildWitness, raw []byte) (SourcePolicyV1, error) {
	var p SourcePolicyV1
	if !w.valid() || sha256Text(raw) != w.inputs.SourcePolicySHA256 || parseCanonical(raw, &p) != nil || p.Validate() != nil {
		return p, ErrInputs
	}
	return p, nil
}
func ParseNativeToolchainInputsV1(w NativeBuildWitness, raw []byte) (ToolchainInputsV1, error) {
	var v ToolchainInputsV1
	if !w.valid() || sha256Text(raw) != w.inputs.ToolchainSHA256 || parseCanonical(raw, &v) != nil || v.Validate() != nil {
		return v, ErrInputs
	}
	return v, nil
}

type sourceIdentity struct{ inputSHA, policySHA, toolchainSHA, commit, repository, version string }

func (v sourceIdentity) valid() bool {
	return digestText.MatchString(v.inputSHA) && digestText.MatchString(v.policySHA) && digestText.MatchString(v.toolchainSHA) && commitText.MatchString(v.commit) && validGitHubRepository(v.repository) && versionText.MatchString(v.version)
}
func sourceIdentityFromWitness(w Witness) sourceIdentity {
	sha, _ := w.SHA256()
	d := w.decision
	return sourceIdentity{sha, d.SourcePolicySHA256, d.ToolchainSHA256, d.SourceCommit, d.SourceRepository, d.Version}
}

var nativeFixedTargets = []struct{ name, path, identity string }{
	{"acornfox-core", "./cmd/acornfox-core", ""},
	{"acornfox", "./cmd/acornfox", ""},
	{"acornfox-host-helper", "./cmd/acornfox-host-helper", ""},
	{"acornfox-container", "./cmd/acornfox-container", ""},
}

// This is only the eight accepted AcornFox product executables. Upstream
// dependency bytes and a trusted unified manifest remain separate missing
// inputs to a complete release.
var nativeProductFixedTargets = []struct{ name, path, identity string }{
	{"acornfox-core", "./cmd/acornfox-core", ""},
	{"acornfox", "./cmd/acornfox", ""},
	{"acornfox-host-helper", "./cmd/acornfox-host-helper", ""},
	{"acornfox-container", "./cmd/acornfox-container", ""},
	{"acornfox-source-build", "./cmd/acornfox-source-build", ""},
	{"acornfox-gateway", "./cmd/acornfox-gateway", ""},
	{"acornfox-host-update", "./cmd/acornfox-host-update", ""},
	{"acornfox-build-network", "./cmd/acornfox-build-network", ""},
}

func nativeProductTargets() []GoBuildTargetV1 {
	out := make([]GoBuildTargetV1, 0, len(nativeProductFixedTargets))
	for _, t := range nativeProductFixedTargets {
		out = append(out, GoBuildTargetV1{t.name, t.path, "bin/" + t.name, []string{"-buildid="}})
	}
	return out
}

func nativeProductPackagePaths(module string) []string {
	out := make([]string, 0, len(nativeProductFixedTargets))
	for _, t := range nativeProductFixedTargets {
		out = append(out, module+"/"+strings.TrimPrefix(t.path, "./"))
	}
	return out
}

func nativeProductTargetsMatch(targets []GoBuildTargetV1, packages []string, module string) bool {
	want := nativeProductTargets()
	if len(targets) != len(want) || !slices.Equal(packages, nativeProductPackagePaths(module)) {
		return false
	}
	for i, t := range targets {
		v := want[i]
		if t.Name != v.Name || t.Package != v.Package || t.Output != v.Output || !slices.Equal(t.Ldflags, v.Ldflags) {
			return false
		}
	}
	return true
}

func nativeTargets() []GoBuildTargetV1 {
	out := make([]GoBuildTargetV1, 0, len(nativeFixedTargets))
	for _, t := range nativeFixedTargets {
		out = append(out, GoBuildTargetV1{t.name, t.path, "bin/" + t.name, []string{"-buildid="}})
	}
	return out
}
func nativePackagePaths(module string) []string {
	out := make([]string, 0, len(nativeFixedTargets))
	for _, t := range nativeFixedTargets {
		out = append(out, module+"/"+strings.TrimPrefix(t.path, "./"))
	}
	return out
}
func nativeTargetsMatch(targets []GoBuildTargetV1, packages []string, module string) bool {
	want := nativeTargets()
	if len(targets) != len(want) || !slices.Equal(packages, nativePackagePaths(module)) {
		return false
	}
	for i, t := range targets {
		v := want[i]
		if t.Name != v.Name || t.Package != v.Package || t.Output != v.Output || !slices.Equal(t.Ldflags, v.Ldflags) {
			return false
		}
	}
	return true
}
func PrepareNativeBuildPlanV1(ctx context.Context, w NativeBuildWitness, policy SourcePolicyV1, tools ToolchainInputsV1, source, cache, npmCLI string) (GoBuildPlanV1, error) {
	if !w.valid() {
		return GoBuildPlanV1{}, ErrGoPlan
	}
	v := w.inputs
	identity := sourceIdentity{w.sha, v.SourcePolicySHA256, v.ToolchainSHA256, v.SourceCommit, v.SourceRepository, v.Version}
	targets := nativeTargets()
	if v.Profile == "native_product" {
		targets = nativeProductTargets()
	}
	return prepareGoBuildPlanIdentity(ctx, identity, true, "", "", targets, policy, tools, source, cache, npmCLI, localGoCommand, exec.LookPath, hashTrustedExecutable)
}

// NativePartialReceiptV1 is an inventory only, never a unified release manifest.
type NativePartialReceiptV1 struct {
	SchemaVersion      int           `json:"schema_version"`
	Profile            string        `json:"profile"`
	Architecture       string        `json:"architecture"`
	Version            string        `json:"version"`
	SourceRepository   string        `json:"source_repository"`
	SourceCommit       string        `json:"source_commit"`
	InputsSHA256       string        `json:"inputs_sha256"`
	SourcePolicySHA256 string        `json:"source_policy_sha256"`
	ToolchainSHA256    string        `json:"toolchain_sha256"`
	TreeSHA256         string        `json:"tree_sha256"`
	Files              []FileEntryV1 `json:"files"`
}

func (r NativePartialReceiptV1) Validate() error {
	return validateNativeBuildReceipt(r, "native_partial", nativeFixedTargets)
}

// NativeProductReceiptV1 is still product bytes only: no build-network policy
// executor, dependency closure, unified manifest, or install readiness.
type NativeProductReceiptV1 NativePartialReceiptV1

func (r NativeProductReceiptV1) Validate() error {
	return validateNativeBuildReceipt(NativePartialReceiptV1(r), "native_product", nativeProductFixedTargets)
}

func validateNativeBuildReceipt(r NativePartialReceiptV1, profile string, targets []struct{ name, path, identity string }) error {
	if r.SchemaVersion != 1 || r.Profile != profile || r.Architecture != Architecture || !versionText.MatchString(r.Version) || !validGitHubRepository(r.SourceRepository) || !commitText.MatchString(r.SourceCommit) || !digestText.MatchString(r.InputsSHA256) || !digestText.MatchString(r.SourcePolicySHA256) || !digestText.MatchString(r.ToolchainSHA256) || !digestText.MatchString(r.TreeSHA256) || validateEntries(r.Files) != nil {
		return ErrInputs
	}
	want := map[string]bool{}
	for _, t := range targets {
		want["bin/"+t.name] = true
	}
	core, metadata := false, false
	for _, f := range r.Files {
		if want[f.Path] && f.Mode == 0o755 {
			delete(want, f.Path)
			continue
		}
		if !strings.HasPrefix(f.Path, "web/") || f.Mode != 0o644 {
			return ErrInputs
		}
		core = core || f.Path == "web/core.html"
		metadata = metadata || f.Path == "web/build-metadata.json"
	}
	raw, err := json.Marshal(r.Files)
	if err != nil || len(want) != 0 || !core || !metadata || sha256Text(raw) != r.TreeSHA256 {
		return ErrInputs
	}
	return nil
}

// BuildNativePartialV1 uses the same frozen offline stages and pinned file-copy
// primitive as V1, and exports only the four native binaries plus Core UI.
func BuildNativePartialV1(ctx context.Context, plan GoBuildPlanV1, goParent, webParent, npmCache, output string) (NativePartialReceiptV1, error) {
	if plan.nativeProduct {
		return NativePartialReceiptV1{}, ErrGoPlan
	}
	return buildNativeCandidate(ctx, plan, goParent, webParent, npmCache, output, "native_partial")
}

func BuildNativeProductV1(ctx context.Context, plan GoBuildPlanV1, goParent, webParent, npmCache, output string) (NativeProductReceiptV1, error) {
	if !plan.nativeProduct {
		return NativeProductReceiptV1{}, ErrGoPlan
	}
	r, err := buildNativeCandidate(ctx, plan, goParent, webParent, npmCache, output, "native_product")
	return NativeProductReceiptV1(r), err
}

func buildNativeCandidate(ctx context.Context, plan GoBuildPlanV1, goParent, webParent, npmCache, output, profile string) (NativePartialReceiptV1, error) {
	var receipt NativePartialReceiptV1
	if !plan.nativePartial || !plan.Valid() || (profile == "native_product") != plan.nativeProduct {
		return receipt, ErrGoPlan
	}
	goStage, err := buildGoBinariesV1(ctx, plan, goParent, plan.goExecutable.run, nil)
	if err != nil {
		return receipt, err
	}
	defer goStage.Close()
	webStage, err := buildWebAssetsV1(ctx, plan, webParent, npmCache, plan.nodeExecutable.run)
	if err != nil {
		return receipt, err
	}
	defer webStage.Close()
	if !goStage.valid() || !webStage.parentPin.validAt(webStage.parent) || !webStage.stagePin.validAt(webStage.root) || !webStage.npmCache.valid() {
		return receipt, ErrGoStage
	}
	webFiles, err := inspectWebDist(webStage.dist, plan)
	if err != nil || !sameFileEntries(webFiles, webStage.receipt.Files) {
		return receipt, ErrWebStage
	}
	if !filepath.IsAbs(output) || filepath.Clean(output) != output || pathWithin(plan.sourceRoot, output) {
		return receipt, ErrGoStage
	}
	parent, pin, err := pinStageParent(filepath.Dir(output))
	if err != nil {
		return receipt, err
	}
	defer pin.close()
	output = filepath.Join(parent, filepath.Base(output))
	if err := os.Mkdir(output, 0o700); err != nil {
		return receipt, err
	}
	outputPin, err := pinDirectory(output)
	if err != nil {
		return receipt, ErrGoStage
	}
	defer outputPin.close()
	success := false
	defer func() {
		if !success && pin.validAt(parent) && outputPin.validAt(output) {
			_ = os.RemoveAll(output)
		}
	}()
	target, err := os.OpenRoot(output)
	if err != nil {
		return receipt, err
	}
	defer target.Close()
	files := append([]FileEntryV1(nil), goStage.receipt.Files...)
	for _, f := range files {
		if err := copyCandidateFile(goStage.root, f.Path, target, f.Path, f, f.Mode, maxGoBinaryOutputBytes); err != nil {
			return receipt, err
		}
	}
	for _, f := range webFiles {
		if err := copyCandidateFile(webStage.dist, f.Path, target, "web/"+f.Path, f, f.Mode, maxWebDistMemberBytes); err != nil {
			return receipt, err
		}
		f.Path = "web/" + f.Path
		files = append(files, f)
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	raw, _ := json.Marshal(files)
	receipt = NativePartialReceiptV1{1, profile, Architecture, plan.releaseVersion, plan.sourceRepositoryURL, plan.sourceCommit, plan.decisionSHA256, plan.sourcePolicySHA256, plan.toolchainSHA256, sha256Text(raw), files}
	validation := receipt.Validate()
	if plan.nativeProduct {
		validation = NativeProductReceiptV1(receipt).Validate()
	}
	if validation != nil || !goStage.valid() || VerifySourceTree(plan.sourceRoot, plan.sourcePolicy) != nil || !pin.validAt(parent) || !outputPin.validAt(output) || verifyFileTree(output, files, false, treeLimits{maxGoBinaryOutputBytes, runtimeTreeBytes}) != nil {
		return NativePartialReceiptV1{}, ErrGoStage
	}
	verifyCtx, cancel := context.WithTimeout(ctx, maxGoPlanObservation)
	defer cancel()
	identity := sourceIdentity{plan.decisionSHA256, plan.sourcePolicySHA256, plan.toolchainSHA256, plan.sourceCommit, plan.sourceRepositoryURL, plan.releaseVersion}
	if err := finishNativePartialOutput(parent, pin, output, outputPin, files, func() error {
		return verifyGitSourceIdentity(verifyCtx, plan.sourceRoot, identity, plan.sourcePolicy, plan.toolchain, localCommand, exec.LookPath, hashTrustedExecutable)
	}); err != nil {
		return NativePartialReceiptV1{}, err
	}
	success = true
	return receipt, nil
}

// Observe Git before the final output pin/hash checks: a slow final source
// observation must never open a window for an unverified replacement export.
func finishNativePartialOutput(parent string, parentPin *directoryPin, output string, outputPin *directoryPin, files []FileEntryV1, observeSource func() error) error {
	if err := observeSource(); err != nil {
		return err
	}
	if !parentPin.validAt(parent) || !outputPin.validAt(output) || verifyFileTree(output, files, false, treeLimits{maxGoBinaryOutputBytes, runtimeTreeBytes}) != nil {
		return ErrGoStage
	}
	return nil
}
