package acornfoxrelease

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

var ErrWebStage = errors.New("acornfox web stage is invalid")

type WebBuildReceiptV1 struct {
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

func (r WebBuildReceiptV1) Validate() error {
	if r.SchemaVersion != 1 || r.Product != Product || r.Architecture != Architecture || !commitText.MatchString(r.SourceCommit) || !digestText.MatchString(r.DecisionSHA256) || !digestText.MatchString(r.SourcePolicySHA256) || !digestText.MatchString(r.ToolchainSHA256) || !digestText.MatchString(r.TreeSHA256) || validateEntries(r.Files) != nil {
		return ErrWebStage
	}
	raw, err := json.Marshal(r.Files)
	if err != nil || sha256Text(raw) != r.TreeSHA256 {
		return ErrWebStage
	}
	return nil
}

type WebAssetStageV1 struct {
	root, parent          string
	parentInfo, stageInfo os.FileInfo
	receipt               WebBuildReceiptV1
	dist                  string
	plan                  GoBuildPlanV1
	closed                bool
}

func BuildWebAssetsV1(ctx context.Context, plan GoBuildPlanV1, taskRoot, npmCacheRoot string) (*WebAssetStageV1, error) {
	return buildWebAssetsV1(ctx, plan, taskRoot, npmCacheRoot, plan.nodeExecutable.run)
}

func buildWebAssetsV1(ctx context.Context, plan GoBuildPlanV1, taskRoot, npmCacheRoot string, runner goCommandRunner) (*WebAssetStageV1, error) {
	if ctx == nil || ctx.Err() != nil || !plan.Valid() || runner == nil || VerifySourceTree(plan.sourceRoot, plan.sourcePolicy) != nil {
		return nil, ErrWebStage
	}
	taskRoot, parentInfo, err := pinStageParent(taskRoot)
	if err != nil {
		return nil, ErrWebStage
	}
	npmCacheRoot, _, err = pinStageParent(npmCacheRoot)
	if err != nil || npmCacheRoot == taskRoot || pathWithin(taskRoot, npmCacheRoot) || pathWithin(npmCacheRoot, taskRoot) {
		return nil, ErrWebStage
	}
	stageRoot, err := os.MkdirTemp(taskRoot, ".acornfox-web-stage-")
	if err != nil {
		return nil, ErrWebStage
	}
	stageInfo, err := os.Lstat(stageRoot)
	stage := &WebAssetStageV1{root: stageRoot, parent: taskRoot, parentInfo: parentInfo, stageInfo: stageInfo}
	fail := func() (*WebAssetStageV1, error) {
		if samePinnedDirectory(stage.parent, stage.parentInfo) && samePinnedDirectory(stage.root, stage.stageInfo) {
			_ = os.RemoveAll(stage.root)
		}
		return nil, ErrWebStage
	}
	if err != nil || os.Chmod(stageRoot, 0o700) != nil {
		return fail()
	}
	frozen, work := filepath.Join(stageRoot, "frozen"), filepath.Join(stageRoot, "work")
	for _, path := range []string{frozen, work, filepath.Join(stageRoot, "tmp"), filepath.Join(stageRoot, "home")} {
		if err := os.Mkdir(path, 0o700); err != nil {
			return fail()
		}
	}
	if err := copyFrozenSource(plan.sourceRoot, frozen, plan.sourcePolicy); err != nil || VerifySourceTree(plan.sourceRoot, plan.sourcePolicy) != nil || VerifySourceTree(frozen, plan.sourcePolicy) != nil {
		return fail()
	}
	webRoot := filepath.Join(work, "web")
	if err := copyFrozenWeb(frozen, webRoot, plan.sourcePolicy); err != nil {
		return fail()
	}
	env, err := webStageEnvironment(plan.Environment(), stageRoot, npmCacheRoot, plan)
	if err != nil {
		return fail()
	}
	node := plan.nodeExecutable
	node.run = runner
	runNPM := func(args ...string) ([]byte, error) { return runNPMCLI(ctx, node, plan.npmCLI, args, webRoot, env) }
	if output, err := node.Run(ctx, []string{"--version"}, webRoot, env); err != nil || strings.TrimSpace(string(output)) != plan.toolchain.NodeVersion {
		return fail()
	}
	if output, err := runNPM("--version"); err != nil || strings.TrimSpace(string(output)) != plan.toolchain.NPMVersion {
		return fail()
	}
	if _, err := runNPM("cache", "verify"); err != nil {
		return fail()
	}
	if _, err := runNPM("ci", "--offline", "--ignore-scripts", "--no-audit", "--no-fund"); err != nil {
		return fail()
	}
	if _, err := node.Run(ctx, []string{filepath.Join(webRoot, "node_modules", "typescript", "bin", "tsc"), "--noEmit"}, webRoot, env); err != nil {
		return fail()
	}
	if _, err := node.Run(ctx, []string{filepath.Join(webRoot, "node_modules", "vite", "bin", "vite.js"), "build", "--mode", "acornfox-release"}, webRoot, env); err != nil {
		return fail()
	}
	if _, err := runNPM("cache", "verify"); err != nil || !plan.npmCLI.valid() || !plan.cache.valid() {
		return fail()
	}
	files, err := inspectWebDist(filepath.Join(webRoot, "dist"), plan)
	if err != nil {
		return fail()
	}
	stage.dist, stage.plan = filepath.Join(webRoot, "dist"), plan
	tree, _ := json.Marshal(files)
	stage.receipt = WebBuildReceiptV1{1, Product, Architecture, plan.sourceCommit, plan.decisionSHA256, plan.sourcePolicySHA256, plan.toolchainSHA256, sha256Text(tree), files}
	if stage.receipt.Validate() != nil {
		return fail()
	}
	return stage, nil
}

func (stage *WebAssetStageV1) Receipt() (WebBuildReceiptV1, error) {
	if stage == nil || stage.closed || stage.receipt.Validate() != nil || !samePinnedDirectory(stage.parent, stage.parentInfo) || !samePinnedDirectory(stage.root, stage.stageInfo) {
		return WebBuildReceiptV1{}, ErrWebStage
	}
	files, err := inspectWebDist(stage.dist, stage.plan)
	if err != nil || !sameFileEntries(files, stage.receipt.Files) {
		return WebBuildReceiptV1{}, ErrWebStage
	}
	copy := stage.receipt
	copy.Files = append([]FileEntryV1(nil), stage.receipt.Files...)
	return copy, nil
}
func (stage *WebAssetStageV1) Close() error {
	if stage == nil || stage.closed {
		return nil
	}
	if !samePinnedDirectory(stage.parent, stage.parentInfo) || !samePinnedDirectory(stage.root, stage.stageInfo) {
		return ErrWebStage
	}
	if err := os.RemoveAll(stage.root); err != nil {
		return ErrWebStage
	}
	stage.closed = true
	return nil
}

func copyFrozenWeb(frozen, destination string, policy SourcePolicyV1) error {
	if err := os.Mkdir(destination, 0o700); err != nil {
		return ErrWebStage
	}
	for _, entry := range policy.Files {
		if !strings.HasPrefix(entry.Path, "web/") {
			continue
		}
		rel := strings.TrimPrefix(entry.Path, "web/")
		if rel == "" {
			return ErrWebStage
		}
		out := filepath.Join(destination, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(out), 0o700); err != nil {
			return ErrWebStage
		}
		input, err := os.Open(filepath.Join(frozen, filepath.FromSlash(entry.Path)))
		if err != nil {
			return ErrWebStage
		}
		output, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, os.FileMode(entry.Mode))
		if err != nil {
			input.Close()
			return ErrWebStage
		}
		_, copyErr := io.Copy(output, input)
		closeOut := output.Close()
		closeIn := input.Close()
		if copyErr != nil || closeOut != nil || closeIn != nil || os.Chmod(out, os.FileMode(entry.Mode)) != nil {
			return ErrWebStage
		}
	}
	if _, err := os.Stat(filepath.Join(destination, "package.json")); err != nil {
		return ErrWebStage
	}
	return nil
}

func webStageEnvironment(base []string, stageRoot, npmCacheRoot string, plan GoBuildPlanV1) ([]string, error) {
	values := map[string]string{}
	order := make([]string, 0, len(base))
	for _, value := range base {
		key, _, ok := strings.Cut(value, "=")
		if !ok || values[key] != "" {
			return nil, ErrWebStage
		}
		values[key] = value
		order = append(order, key)
	}
	set := func(key, value string) {
		if values[key] == "" {
			order = append(order, key)
		}
		values[key] = key + "=" + value
	}
	set("HOME", filepath.Join(stageRoot, "home"))
	set("TMPDIR", filepath.Join(stageRoot, "tmp"))
	set("npm_config_cache", npmCacheRoot)
	set("npm_config_offline", "true")
	set("npm_config_ignore_scripts", "true")
	set("npm_config_audit", "false")
	set("npm_config_fund", "false")
	set("npm_config_update_notifier", "false")
	set("HTTP_PROXY", "")
	set("HTTPS_PROXY", "")
	set("ALL_PROXY", "")
	set("VITE_API_MODE", "live")
	set("VITE_API_BASE_URL", "/api/v1")
	set("ACORNFOX_RELEASE_VERSION", plan.releaseVersion)
	set("ACORNFOX_SOURCE_REPOSITORY", plan.sourceRepositoryURL)
	set("ACORNFOX_SOURCE_COMMIT", plan.sourceCommit)
	out := make([]string, 0, len(order))
	for _, key := range order {
		out = append(out, values[key])
	}
	return out, nil
}

func inspectWebDist(root string, plan GoBuildPlanV1) ([]FileEntryV1, error) {
	var files []FileEntryV1
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		if strings.HasPrefix(filepath.Base(rel), ".") || entry.Type()&os.ModeSymlink != 0 {
			return ErrWebStage
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o644 || linkCount(info) != 1 {
			return ErrWebStage
		}
		body, err := os.ReadFile(path)
		if err != nil || len(body) > 16<<20 {
			return ErrWebStage
		}
		files = append(files, FileEntryV1{filepath.ToSlash(rel), sha256Text(body), 0o644})
		return nil
	})
	if err != nil || len(files) == 0 {
		return nil, ErrWebStage
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	metadataRaw, err := os.ReadFile(filepath.Join(root, "build-metadata.json"))
	if err != nil {
		return nil, ErrWebStage
	}
	var metadata struct {
		APIMode          string `json:"mode"`
		APIBaseURL       string `json:"apiBaseUrl"`
		Schema           string `json:"schemaVersion"`
		ReleaseID        string `json:"releaseId"`
		Version          string `json:"version"`
		SourceRepository string `json:"sourceRepository"`
		SourceCommit     string `json:"sourceCommit"`
	}
	if json.Unmarshal(metadataRaw, &metadata) != nil || metadata.APIMode != "acornfox-release" || metadata.APIBaseURL != "/api/v1" || metadata.Schema != "acornfox-release-build-attestation.v1" || metadata.Version != plan.releaseVersion || metadata.ReleaseID != "release-"+plan.releaseVersion || metadata.SourceRepository != plan.sourceRepositoryURL || metadata.SourceCommit != plan.sourceCommit {
		return nil, ErrWebStage
	}
	return files, nil
}
