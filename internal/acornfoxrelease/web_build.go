package acornfoxrelease

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
)

var ErrWebStage = errors.New("acornfox web stage is invalid")

type WebBuildReceiptV1 struct {
	SchemaVersion      int           `json:"schema_version"`
	Product            string        `json:"product"`
	Architecture       string        `json:"architecture"`
	Version            string        `json:"version"`
	ReleaseID          string        `json:"release_id"`
	SourceRepository   string        `json:"source_repository"`
	SourceCommit       string        `json:"source_commit"`
	DecisionSHA256     string        `json:"decision_sha256"`
	SourcePolicySHA256 string        `json:"source_policy_sha256"`
	ToolchainSHA256    string        `json:"toolchain_sha256"`
	TreeSHA256         string        `json:"tree_sha256"`
	Files              []FileEntryV1 `json:"files"`
}

func (r WebBuildReceiptV1) Validate() error {
	if r.SchemaVersion != 1 || r.Product != Product || r.Architecture != Architecture || !versionText.MatchString(r.Version) || r.ReleaseID != "release-"+r.Version || !validGitHubRepository(r.SourceRepository) || !commitText.MatchString(r.SourceCommit) || !digestText.MatchString(r.DecisionSHA256) || !digestText.MatchString(r.SourcePolicySHA256) || !digestText.MatchString(r.ToolchainSHA256) || !digestText.MatchString(r.TreeSHA256) || validateWebEntries(r.Files) != nil {
		return ErrWebStage
	}
	raw, err := json.Marshal(r.Files)
	if err != nil || sha256Text(raw) != r.TreeSHA256 {
		return ErrWebStage
	}
	return nil
}

func validateWebEntries(entries []FileEntryV1) error {
	if len(entries) == 0 || len(entries) > maxWebDistFiles {
		return ErrWebStage
	}
	for index, entry := range entries {
		if !validRelativeFile(entry.Path) || !digestText.MatchString(entry.SHA256) || entry.Mode != 0o644 || index > 0 && entries[index-1].Path >= entry.Path {
			return ErrWebStage
		}
	}
	return nil
}

type WebAssetStageV1 struct {
	root, parent          string
	parentInfo, stageInfo os.FileInfo
	receipt               WebBuildReceiptV1
	dist                  string
	plan                  GoBuildPlanV1
	npmCache              pinnedNPMCache
	closed                bool
}

type pinnedNPMCache struct {
	path string
	info os.FileInfo
}

func pinNPMCache(path string) (pinnedNPMCache, error) {
	path, err := cleanExistingDirectory(path)
	if err != nil {
		return pinnedNPMCache{}, ErrWebStage
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode().Perm() != 0o700 || info.Mode()&os.ModeSymlink != 0 {
		return pinnedNPMCache{}, ErrWebStage
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); !ok || int(stat.Uid) != os.Getuid() {
		return pinnedNPMCache{}, ErrWebStage
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return pinnedNPMCache{}, ErrWebStage
	}
	defer root.Close()
	opened, err := root.Stat(".")
	if err != nil || opened.Mode().Perm() != 0o700 || !os.SameFile(info, opened) {
		return pinnedNPMCache{}, ErrWebStage
	}
	return pinnedNPMCache{path: path, info: opened}, nil
}
func (cache pinnedNPMCache) valid() bool {
	info, err := os.Lstat(cache.path)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 || info.Mode()&os.ModeSymlink != 0 || !os.SameFile(info, cache.info) {
		return false
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); !ok || int(stat.Uid) != os.Getuid() {
		return false
	}
	root, err := os.OpenRoot(cache.path)
	if err != nil {
		return false
	}
	defer root.Close()
	opened, err := root.Stat(".")
	return err == nil && opened.IsDir() && opened.Mode().Perm() == 0o700 && os.SameFile(cache.info, opened)
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
	npmCache, err := pinNPMCache(npmCacheRoot)
	if err != nil || npmCache.path == taskRoot || pathWithin(taskRoot, npmCache.path) || pathWithin(npmCache.path, taskRoot) {
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
	env, err := webStageEnvironment(plan.Environment(), stageRoot, npmCache.path, plan)
	if err != nil {
		return fail()
	}
	node := plan.nodeExecutable
	node.run = runner
	runNPM := func(args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] != "--version" && !npmCache.valid() {
			return nil, ErrWebStage
		}
		out, err := runNPMCLI(ctx, node, plan.npmCLI, args, webRoot, env)
		if len(args) > 0 && args[0] != "--version" && !npmCache.valid() {
			return nil, ErrWebStage
		}
		return out, err
	}
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
	if _, err := runNPM("cache", "verify"); err != nil || !plan.npmCLI.valid() || !plan.cache.valid() || !npmCache.valid() {
		return fail()
	}
	files, err := inspectWebDist(filepath.Join(webRoot, "dist"), plan)
	if err != nil {
		return fail()
	}
	stage.dist, stage.plan, stage.npmCache = filepath.Join(webRoot, "dist"), plan, npmCache
	tree, _ := json.Marshal(files)
	stage.receipt = WebBuildReceiptV1{
		SchemaVersion:      1,
		Product:            Product,
		Architecture:       Architecture,
		Version:            plan.releaseVersion,
		ReleaseID:          "release-" + plan.releaseVersion,
		SourceRepository:   plan.sourceRepositoryURL,
		SourceCommit:       plan.sourceCommit,
		DecisionSHA256:     plan.decisionSHA256,
		SourcePolicySHA256: plan.sourcePolicySHA256,
		ToolchainSHA256:    plan.toolchainSHA256,
		TreeSHA256:         sha256Text(tree),
		Files:              append([]FileEntryV1(nil), files...),
	}
	if stage.receipt.Validate() != nil {
		return fail()
	}
	return stage, nil
}

func (stage *WebAssetStageV1) Receipt() (WebBuildReceiptV1, error) {
	if stage == nil || stage.closed || stage.receipt.Validate() != nil || !samePinnedDirectory(stage.parent, stage.parentInfo) || !samePinnedDirectory(stage.root, stage.stageInfo) || !stage.npmCache.valid() {
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

const (
	maxWebDistFiles         = 4096
	maxWebDistMemberBytes   = int64(16 << 20)
	maxWebDistTotalBytes    = int64(128 << 20)
	maxWebMetadataBytes     = int64(64 << 10)
	webReleaseSchemaVersion = "acornfox-release-build-attestation.v1"
)

func inspectWebDist(path string, plan GoBuildPlanV1) ([]FileEntryV1, error) {
	outer, err := os.Lstat(path)
	if err != nil || !outer.IsDir() || outer.Mode()&os.ModeSymlink != 0 {
		return nil, ErrWebStage
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, ErrWebStage
	}
	defer root.Close()
	opened, err := root.Stat(".")
	if err != nil || !opened.IsDir() || !os.SameFile(outer, opened) {
		return nil, ErrWebStage
	}

	var files []FileEntryV1
	var metadataRaw []byte
	var total int64
	err = fs.WalkDir(root.FS(), ".", func(rel string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil || rel == "" {
			return ErrWebStage
		}
		if rel == "." {
			return nil
		}
		for _, component := range strings.Split(rel, "/") {
			if component == "" || component == "." || component == ".." || strings.HasPrefix(component, ".") {
				return ErrWebStage
			}
		}
		before, err := root.Lstat(rel)
		if err != nil || before.Mode()&os.ModeSymlink != 0 {
			return ErrWebStage
		}
		if before.IsDir() {
			return nil
		}
		if !before.Mode().IsRegular() || before.Mode().Perm() != 0o644 || linkCount(before) != 1 || before.Size() < 0 || before.Size() > maxWebDistMemberBytes || len(files) >= maxWebDistFiles || before.Size() > maxWebDistTotalBytes-total {
			return ErrWebStage
		}
		if rel == "build-metadata.json" && before.Size() > maxWebMetadataBytes {
			return ErrWebStage
		}
		total += before.Size()
		file, err := root.OpenFile(rel, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if err != nil {
			return ErrWebStage
		}
		opened, statErr := file.Stat()
		if statErr != nil || !opened.Mode().IsRegular() || opened.Mode().Perm() != 0o644 || linkCount(opened) != 1 || opened.Size() != before.Size() || !os.SameFile(before, opened) {
			_ = file.Close()
			return ErrWebStage
		}
		hash := sha256.New()
		var capture bytes.Buffer
		writer := io.Writer(hash)
		if rel == "build-metadata.json" {
			writer = io.MultiWriter(hash, &capture)
		}
		n, readErr := io.Copy(writer, io.LimitReader(file, maxWebDistMemberBytes+1))
		closeErr := file.Close()
		after, afterErr := root.Lstat(rel)
		if readErr != nil || closeErr != nil || afterErr != nil || n != before.Size() || n > maxWebDistMemberBytes || !os.SameFile(before, after) {
			return ErrWebStage
		}
		if rel == "build-metadata.json" {
			metadataRaw = append([]byte(nil), capture.Bytes()...)
		}
		files = append(files, FileEntryV1{Path: rel, SHA256: hex.EncodeToString(hash.Sum(nil)), Mode: 0o644})
		return nil
	})
	if err != nil || len(files) == 0 || len(metadataRaw) == 0 {
		return nil, ErrWebStage
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	if parseWebMetadata(metadataRaw, plan) != nil {
		return nil, ErrWebStage
	}
	return files, nil
}

func parseWebMetadata(raw []byte, plan GoBuildPlanV1) error {
	if len(raw) == 0 || int64(len(raw)) > maxWebMetadataBytes {
		return ErrWebStage
	}
	type metadataV1 struct {
		APIBaseURL       string `json:"apiBaseUrl"`
		Mode             string `json:"mode"`
		Product          string `json:"product"`
		ReleaseID        string `json:"releaseId"`
		SchemaVersion    string `json:"schemaVersion"`
		SourceCommit     string `json:"sourceCommit"`
		SourceRepository string `json:"sourceRepository"`
		Version          string `json:"version"`
	}
	want := map[string]bool{
		"apiBaseUrl": true, "mode": true, "product": true, "releaseId": true,
		"schemaVersion": true, "sourceCommit": true, "sourceRepository": true, "version": true,
	}
	keyDecoder := json.NewDecoder(bytes.NewReader(raw))
	start, err := keyDecoder.Token()
	if err != nil || start != json.Delim('{') {
		return ErrWebStage
	}
	seen := make(map[string]bool, len(want))
	for keyDecoder.More() {
		token, err := keyDecoder.Token()
		key, ok := token.(string)
		if err != nil || !ok || !want[key] || seen[key] {
			return ErrWebStage
		}
		var value json.RawMessage
		if err := keyDecoder.Decode(&value); err != nil {
			return ErrWebStage
		}
		seen[key] = true
	}
	end, err := keyDecoder.Token()
	var trailing any
	if err != nil || end != json.Delim('}') || len(seen) != len(want) || keyDecoder.Decode(&trailing) != io.EOF {
		return ErrWebStage
	}
	var metadata metadataV1
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&metadata); err != nil {
		return ErrWebStage
	}
	if err := decoder.Decode(&trailing); err != io.EOF {
		return ErrWebStage
	}
	if metadata.Product != Product || metadata.Mode != "live" || metadata.APIBaseURL != "/api/v1" || metadata.SchemaVersion != webReleaseSchemaVersion || metadata.Version != plan.releaseVersion || metadata.ReleaseID != "release-"+plan.releaseVersion || metadata.SourceRepository != plan.sourceRepositoryURL || metadata.SourceCommit != plan.sourceCommit {
		return ErrWebStage
	}
	return nil
}
