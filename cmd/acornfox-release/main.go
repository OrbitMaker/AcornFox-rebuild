// Command acornfox-release builds a verified, unapproved release candidate.
// Dependency downloads and host/public acceptance are separate operations.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/open-card/open-card/internal/acornfoxrelease"
	"github.com/open-card/open-card/internal/install"
)

type options struct {
	predecessorBinding, predecessorSHA                                             string
	source, decision, decisionSHA, policy, toolchain, runtimeInputs, licenseInputs string
	runtimeRoot, licenseRoot, cache, npmCache, npmCLI, scratch, output             string
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := run(ctx, os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "acornfox-release:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, out, diagnostic io.Writer) error {
	if len(args) > 0 && args[0] == "native-full-manifest" {
		return runNativeFullManifest(ctx, args[1:], out, diagnostic)
	}
	if len(args) > 0 && args[0] == "native-partial-build" {
		return runNativePartial(ctx, args[1:], out, diagnostic)
	}
	if len(args) > 0 && args[0] == "native-product-build" {
		return runNativeProduct(ctx, args[1:], out, diagnostic)
	}
	if len(args) == 0 || args[0] != "build" {
		return errors.New("usage: acornfox-release build --source DIR --decision FILE --decision-sha256 SHA --source-policy FILE --toolchain FILE --runtime-inputs FILE --license-inputs FILE --runtime-root DIR --license-root DIR --cache DIR --npm-cache DIR --scratch DIR --output DIR [--predecessor-binding FILE --predecessor-sha256 SHA]")
	}
	var o options
	fs := flag.NewFlagSet("build", flag.ContinueOnError)
	fs.SetOutput(diagnostic)
	for _, item := range []struct {
		name  string
		value *string
	}{{"source", &o.source}, {"decision", &o.decision}, {"decision-sha256", &o.decisionSHA}, {"source-policy", &o.policy}, {"toolchain", &o.toolchain}, {"runtime-inputs", &o.runtimeInputs}, {"license-inputs", &o.licenseInputs}, {"runtime-root", &o.runtimeRoot}, {"license-root", &o.licenseRoot}, {"cache", &o.cache}, {"npm-cache", &o.npmCache}, {"npm-cli", &o.npmCLI}, {"scratch", &o.scratch}, {"output", &o.output}, {"predecessor-binding", &o.predecessorBinding}, {"predecessor-sha256", &o.predecessorSHA}} {
		fs.StringVar(item.value, item.name, "", item.name)
	}
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	if (o.predecessorBinding == "") != (o.predecessorSHA == "") {
		return errors.New("predecessor-binding and predecessor-sha256 must be provided together")
	}
	read := readBuildInput

	var predecessorRaw []byte
	if o.predecessorBinding != "" {
		var err error
		predecessorRaw, err = read(o.predecessorBinding)
		if err != nil {
			return fmt.Errorf("read predecessor binding: %w", err)
		}
		if err := install.ParseAcornFoxPredecessorBindingV1(predecessorRaw, o.predecessorSHA); err != nil {
			return fmt.Errorf("verify predecessor binding: %w", err)
		}
	}
	for _, v := range []string{o.source, o.decision, o.decisionSHA, o.policy, o.toolchain, o.runtimeInputs, o.licenseInputs, o.runtimeRoot, o.licenseRoot, o.cache, o.npmCache, o.scratch, o.output} {
		if v == "" {
			return errors.New("all build input and output flags are required")
		}
	}
	if !filepath.IsAbs(o.output) || filepath.Clean(o.output) != o.output {
		return errors.New("output must be an absolute clean path")
	}
	for _, path := range []string{o.scratch, o.cache, o.npmCache, filepath.Dir(o.output)} {
		if err := privateDirectory(path); err != nil {
			return err
		}
	}
	for _, path := range []*string{&o.source, &o.scratch, &o.cache, &o.npmCache, &o.runtimeRoot, &o.licenseRoot} {
		canonical, err := filepath.EvalSymlinks(*path)
		if err != nil {
			return err
		}
		*path, err = filepath.Abs(canonical)
		if err != nil {
			return err
		}
	}
	outputParent, err := filepath.EvalSymlinks(filepath.Dir(o.output))
	if err != nil {
		return err
	}
	o.output = filepath.Join(outputParent, filepath.Base(o.output))
	if _, err := os.Lstat(o.output); !errors.Is(err, os.ErrNotExist) {
		return errors.New("output must not already exist")
	}
	if within(o.source, o.output) || within(o.source, o.scratch) {
		return errors.New("scratch and output must be outside the frozen source")
	}
	if o.npmCLI == "" {
		path, err := exec.LookPath("npm")
		if err != nil {
			return errors.New("npm CLI is unavailable")
		}
		o.npmCLI, err = filepath.EvalSymlinks(path)
		if err != nil {
			return err
		}
	}
	raw, err := read(o.decision)
	if err != nil {
		return err
	}
	witness, err := acornfoxrelease.ParseDecisionV1(raw, o.decisionSHA)
	if err != nil {
		return err
	}
	raw, err = read(o.policy)
	if err != nil {
		return err
	}
	policy, err := acornfoxrelease.ParseSourcePolicyV1(witness, raw)
	if err != nil {
		return err
	}
	raw, err = read(o.toolchain)
	if err != nil {
		return err
	}
	toolchain, err := acornfoxrelease.ParseToolchainInputsV1(witness, raw)
	if err != nil {
		return err
	}
	raw, err = read(o.runtimeInputs)
	if err != nil {
		return err
	}
	runtimeInputs, err := acornfoxrelease.ParseRuntimeInputsV1(witness, raw)
	if err != nil {
		return err
	}
	raw, err = read(o.licenseInputs)
	if err != nil {
		return err
	}
	licenseInputs, err := acornfoxrelease.ParseLicenseInputsV1(witness, raw)
	if err != nil {
		return err
	}
	plan, err := acornfoxrelease.PrepareGoBuildPlanV1(ctx, witness, policy, toolchain, o.source, o.cache, o.npmCLI)
	if err != nil {
		return fmt.Errorf("prepare verified build plan: %w", err)
	}
	defer plan.Close()
	var parents []*tempParent
	defer func() {
		for i := len(parents) - 1; i >= 0; i-- {
			parents[i].close()
		}
	}()
	makeParent := func(label string) (string, error) {
		p, err := newTempParent(o.scratch, label)
		if err != nil {
			return "", err
		}
		parents = append(parents, p)
		return p.path, nil
	}
	path, err := makeParent("go-")
	if err != nil {
		return err
	}
	goStage, err := acornfoxrelease.BuildGoBinariesV1(ctx, plan, path)
	if err != nil {
		return fmt.Errorf("build product binaries: %w", err)
	}
	defer goStage.Close()
	path, err = makeParent("web-")
	if err != nil {
		return err
	}
	webStage, err := acornfoxrelease.BuildWebAssetsV1(ctx, plan, path, o.npmCache)
	if err != nil {
		return fmt.Errorf("build web assets: %w", err)
	}
	defer webStage.Close()
	path, err = makeParent("tree-")
	if err != nil {
		return err
	}
	tree, err := acornfoxrelease.BuildReleaseCandidateTreeV1(plan, goStage, webStage, o.runtimeRoot, runtimeInputs, o.licenseRoot, licenseInputs, path)
	if err != nil {
		return fmt.Errorf("assemble candidate: %w", err)
	}
	defer tree.Close()
	path, err = makeParent("archive-")
	if err != nil {
		return err
	}
	var artifacts *acornfoxrelease.CandidateArtifactStageV1
	if o.predecessorBinding == "" {
		artifacts, err = acornfoxrelease.SealCandidateArtifactsV1(tree, path)
	} else {
		artifacts, err = acornfoxrelease.SealSuccessorCandidateArtifactsV1(tree, path, predecessorRaw, o.predecessorSHA)
	}
	if err != nil {
		return fmt.Errorf("seal candidate: %w", err)
	}
	defer artifacts.Close()
	verified, err := acornfoxrelease.VerifyReleaseCandidateV1(artifacts)
	if err != nil {
		return fmt.Errorf("verify installer inputs: %w", err)
	}
	defer verified.Close()
	receipt, err := acornfoxrelease.ExportVerifiedCandidateV1(verified, o.output)
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(struct {
		Output       string                                     `json:"output"`
		Verification acornfoxrelease.VerifiedCandidateReceiptV1 `json:"verification"`
	}{o.output, receipt})
}

func within(root, path string) bool {
	r, e := filepath.Abs(root)
	p, x := filepath.Abs(path)
	if e != nil || x != nil {
		return true
	}
	rel, e := filepath.Rel(r, p)
	return e == nil && rel != ".." && !filepath.IsAbs(rel) && !(len(rel) > 3 && rel[:3] == "../")
}

type tempParent struct {
	path string
	file *os.File
}

func newTempParent(root, label string) (*tempParent, error) {
	if err := privateDirectory(root); err != nil {
		return nil, err
	}
	path, err := os.MkdirTemp(root, label)
	if err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	return &tempParent{path, file}, nil
}

func privateDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !filepath.IsAbs(path) || !info.IsDir() || info.Mode().Perm() != 0700 || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("cache, scratch and output parents must be prepared private directories")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Getuid() {
		return errors.New("build directories must belong to the current user")
	}
	return nil
}
func (p *tempParent) close() {
	defer p.file.Close()
	opened, e := p.file.Stat()
	current, x := os.Lstat(p.path)
	if e == nil && x == nil && current.IsDir() && current.Mode()&os.ModeSymlink == 0 && os.SameFile(opened, current) {
		_ = os.Remove(p.path)
	}
}

func readBuildInput(path string) ([]byte, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 1<<20 {
		return nil, errors.New("invalid release input file")
	}
	raw, err := io.ReadAll(io.LimitReader(file, (1<<20)+1))
	if err != nil || len(raw) > 1<<20 {
		return nil, errors.New("invalid release input bytes")
	}
	return raw, nil
}

func runNativePartial(ctx context.Context, args []string, out, diagnostic io.Writer) error {
	return runNativeProfile(ctx, args, out, diagnostic, "native_partial")
}

func runNativeProduct(ctx context.Context, args []string, out, diagnostic io.Writer) error {
	return runNativeProfile(ctx, args, out, diagnostic, "native_product")
}

func runNativeProfile(ctx context.Context, args []string, out, diagnostic io.Writer, profile string) error {
	var source, inputs, inputsSHA, policyPath, toolsPath, cache, npmCache, npmCLI, scratch, output string
	if profile != "native_partial" && profile != "native_product" {
		return errors.New("unsupported Native product build profile")
	}
	fs := flag.NewFlagSet(profile+"-build", flag.ContinueOnError)
	fs.SetOutput(diagnostic)
	for _, item := range []struct {
		name  string
		value *string
	}{
		{"source", &source}, {"native-inputs", &inputs}, {"native-inputs-sha256", &inputsSHA}, {"source-policy", &policyPath}, {"toolchain", &toolsPath}, {"cache", &cache}, {"npm-cache", &npmCache}, {"npm-cli", &npmCLI}, {"scratch", &scratch}, {"output", &output},
	} {
		fs.StringVar(item.value, item.name, "", item.name)
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	for _, v := range []string{source, inputs, inputsSHA, policyPath, toolsPath, cache, npmCache, npmCLI, scratch, output} {
		if v == "" {
			return errors.New("all native-partial build input and output flags are required")
		}
	}
	if !filepath.IsAbs(output) || filepath.Clean(output) != output {
		return errors.New("output must be an absolute clean path")
	}
	for _, path := range []string{scratch, cache, npmCache, filepath.Dir(output)} {
		if err := privateDirectory(path); err != nil {
			return err
		}
	}
	for _, path := range []*string{&source, &scratch, &cache, &npmCache} {
		canonical, err := filepath.EvalSymlinks(*path)
		if err != nil {
			return err
		}
		*path, err = filepath.Abs(canonical)
		if err != nil {
			return err
		}
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(output))
	if err != nil {
		return err
	}
	output = filepath.Join(parent, filepath.Base(output))
	if _, err := os.Lstat(output); !errors.Is(err, os.ErrNotExist) {
		return errors.New("output must not already exist")
	}
	if within(source, output) || within(source, scratch) || within(cache, output) || within(npmCache, output) {
		return errors.New("build output and scratch must be outside source and dependency caches")
	}
	raw, err := readBuildInput(inputs)
	if err != nil {
		return err
	}
	witness, err := acornfoxrelease.ParseNativeBuildInputsV1(raw, inputsSHA)
	if err != nil {
		return err
	}
	if witness.Profile() != profile {
		return errors.New("native build command and pinned profile differ")
	}
	raw, err = readBuildInput(policyPath)
	if err != nil {
		return err
	}
	policy, err := acornfoxrelease.ParseNativeSourcePolicyV1(witness, raw)
	if err != nil {
		return err
	}
	raw, err = readBuildInput(toolsPath)
	if err != nil {
		return err
	}
	tools, err := acornfoxrelease.ParseNativeToolchainInputsV1(witness, raw)
	if err != nil {
		return err
	}
	plan, err := acornfoxrelease.PrepareNativeBuildPlanV1(ctx, witness, policy, tools, source, cache, npmCLI)
	if err != nil {
		return fmt.Errorf("prepare native %s: %w", profile, err)
	}
	defer plan.Close()
	goParent, err := newTempParent(scratch, "native-go-")
	if err != nil {
		return err
	}
	defer goParent.close()
	webParent, err := newTempParent(scratch, "native-web-")
	if err != nil {
		return err
	}
	defer webParent.close()
	var receipt any
	if profile == "native_product" {
		product, buildErr := acornfoxrelease.BuildNativeProductV1(ctx, plan, goParent.path, webParent.path, npmCache, output)
		if buildErr != nil {
			return fmt.Errorf("build native product: %w", buildErr)
		}
		receipt = product
	} else {
		partial, buildErr := acornfoxrelease.BuildNativePartialV1(ctx, plan, goParent.path, webParent.path, npmCache, output)
		if buildErr != nil {
			return fmt.Errorf("build native partial: %w", buildErr)
		}
		receipt = partial
	}
	return json.NewEncoder(out).Encode(struct {
		Output  string `json:"output"`
		Receipt any    `json:"receipt"`
	}{output, receipt})
}
