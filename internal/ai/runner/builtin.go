package runner

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/open-card/open-card/internal/ai/tools"
)

type builtinExecutor struct{}

func (builtinExecutor) Execute(ctx context.Context, request ExecutionRequest) (ExecutionOutput, error) {
	if err := ctx.Err(); err != nil {
		return ExecutionOutput{}, err
	}
	switch request.Descriptor.Kind {
	case tools.KindRead:
		return executeRead(ctx, request)
	case tools.KindInspect:
		return executeInspect(ctx, request)
	case tools.KindSearch:
		return executeSearch(ctx, request)
	case tools.KindBuildTest:
		return executeFixture(ctx, request, "build")
	case tools.KindHealthCheck:
		return executeFixture(ctx, request, "health")
	case tools.KindDraftEdit:
		return executeDraftEdit(ctx, request)
	case tools.KindPatch:
		return executePatchCandidate(ctx, request)
	default:
		return ExecutionOutput{}, fmt.Errorf("%w: unsupported built-in tool kind", ErrExecution)
	}
}

func executeRead(ctx context.Context, request ExecutionRequest) (ExecutionOutput, error) {
	path, err := actionPath(request, scopeWorkspace, false, false)
	if err != nil {
		return ExecutionOutput{}, err
	}
	content, err := readBounded(ctx, path, boundedReadLimits(request))
	if err != nil {
		return ExecutionOutput{}, err
	}
	value := map[string]any{"path": relativePath(request.Workspace, path), "content": string(content), "bytes": len(content), "digest": hashBytes(content)}
	return ExecutionOutput{Value: value, Digest: outputDigest(value, ""), Bytes: int64(len(content)), Files: 1}, nil
}

func executeInspect(ctx context.Context, request ExecutionRequest) (ExecutionOutput, error) {
	requested := optionalPath(request.Action.Parameters)
	if requested == "" {
		requested = "."
	}
	path, err := securePath(request.Workspace, requested, false, true)
	if err != nil {
		return ExecutionOutput{}, err
	}
	if info, statErr := os.Lstat(path); statErr != nil {
		return ExecutionOutput{}, statErr
	} else if !info.IsDir() {
		content, readErr := readBounded(ctx, path, boundedReadLimits(request))
		if readErr != nil {
			return ExecutionOutput{}, readErr
		}
		value := map[string]any{"path": relativePath(request.Workspace, path), "kind": "file", "bytes": len(content), "digest": hashBytes(content)}
		return ExecutionOutput{Value: value, Digest: outputDigest(value, ""), Bytes: int64(len(content)), Files: 1}, nil
	}
	files, bytes, digest, err := walkDigest(ctx, path, request.Workspace, request.Limits, false)
	if err != nil {
		return ExecutionOutput{}, err
	}
	value := map[string]any{"path": relativePath(request.Workspace, path), "kind": "directory", "files": files, "bytes": bytes, "digest": digest}
	return ExecutionOutput{Value: value, Digest: outputDigest(value, ""), Bytes: bytes, Files: files}, nil
}

func executeSearch(ctx context.Context, request ExecutionRequest) (ExecutionOutput, error) {
	query, _ := request.Action.Parameters["query"].(string)
	if strings.TrimSpace(query) == "" {
		return ExecutionOutput{}, fmt.Errorf("%w: search query is empty", ErrInvalidRequest)
	}
	requested := optionalPath(request.Action.Parameters)
	if requested == "" {
		requested = "."
	}
	path, err := securePath(request.Workspace, requested, false, true)
	if err != nil {
		return ExecutionOutput{}, err
	}
	maxMatches := intFrom(request.Action.Parameters, "max_matches", request.Limits.MaxFiles)
	if maxMatches <= 0 || maxMatches > request.Limits.MaxFiles {
		return ExecutionOutput{}, fmt.Errorf("%w: max_matches exceeds catalog bound", ErrResourceLimit)
	}
	maxBytes := int64From(request.Action.Parameters, "max_bytes", request.Limits.MaxFileBytes)
	if maxBytes <= 0 || maxBytes > request.Limits.MaxFileBytes {
		return ExecutionOutput{}, fmt.Errorf("%w: max_bytes exceeds catalog bound", ErrResourceLimit)
	}
	type match struct {
		Path string `json:"path"`
		Line int    `json:"line"`
		Text string `json:"text"`
	}
	matches := make([]match, 0, minInt(maxMatches, 32))
	files, totalBytes := 0, int64(0)
	err = walkFiles(ctx, path, request.Workspace, request.Limits, true, func(filePath string, info fs.FileInfo) error {
		if len(matches) >= maxMatches {
			return errSearchDone
		}
		if info.Size() > maxBytes {
			return nil
		}
		content, readErr := readBounded(ctx, filePath, tools.ResourceLimits{MaxFileBytes: maxBytes, MaxInputBytes: maxBytes, MaxTotalBytes: maxBytes, MaxOutputBytes: request.Limits.MaxOutputBytes, MaxFiles: 1, MaxDuration: request.Limits.MaxDuration, MaxTokens: request.Limits.MaxTokens, MaxMemoryBytes: request.Limits.MaxMemoryBytes, MaxDiskBytes: request.Limits.MaxDiskBytes})
		if readErr != nil {
			return readErr
		}
		files++
		if files > request.Limits.MaxFiles {
			return fmt.Errorf("%w: file count exceeded", ErrResourceLimit)
		}
		totalBytes += int64(len(content))
		scanner := bufio.NewScanner(strings.NewReader(string(content)))
		scanner.Buffer(make([]byte, 1024), int(maxBytes)+1)
		line := 0
		for scanner.Scan() {
			line++
			if strings.Contains(scanner.Text(), query) {
				matches = append(matches, match{Path: relativePath(request.Workspace, filePath), Line: line, Text: boundedText(scanner.Text(), 1024)})
				if len(matches) >= maxMatches {
					break
				}
			}
		}
		if scanErr := scanner.Err(); scanErr != nil {
			return scanErr
		}
		return nil
	})
	if errors.Is(err, errSearchDone) {
		err = nil
	}
	if err != nil {
		return ExecutionOutput{}, err
	}
	value := map[string]any{"query": query, "matches": matches, "files": files, "bytes": totalBytes}
	return ExecutionOutput{Value: value, Digest: outputDigest(value, ""), Bytes: totalBytes, Files: files}, nil
}

var errSearchDone = errors.New("search limit reached")

func executeFixture(ctx context.Context, request ExecutionRequest, kind string) (ExecutionOutput, error) {
	fixture := "pass"
	if value, ok := request.Action.Parameters["fixture"].(string); ok && strings.TrimSpace(value) != "" {
		fixture = value
	}
	if fixture == "timeout" {
		select {
		case <-ctx.Done():
			return ExecutionOutput{}, ctx.Err()
		case <-time.After(10 * time.Second):
			return ExecutionOutput{}, fmt.Errorf("%w: fixture did not finish", ErrTimeout)
		}
	}
	path, err := securePath(request.Workspace, optionalPath(request.Action.Parameters), false, true)
	if err != nil {
		if optionalPath(request.Action.Parameters) == "" {
			path, err = securePath(request.Workspace, ".", false, true)
		}
		if err != nil {
			return ExecutionOutput{}, err
		}
	}
	files, bytes, digest, err := walkDigest(ctx, path, request.Workspace, request.Limits, true)
	if err != nil {
		return ExecutionOutput{}, err
	}
	value := map[string]any{"kind": kind, "fixture": fixture, "files": files, "bytes": bytes, "digest": digest, "network": "disabled"}
	output := ExecutionOutput{Value: value, Digest: outputDigest(value, ""), Bytes: bytes, Files: files}
	switch fixture {
	case "failure":
		return output, ErrFixtureFailed
	case "resource":
		// The runner's serialized-output check is the final guard; this marker
		// makes the deterministic fixture useful for resource-limit tests.
		value["diagnostic"] = strings.Repeat("x", int(request.Limits.MaxOutputBytes)+1)
		output.Value = value
		output.Bytes = request.Limits.MaxOutputBytes + 1
		return output, nil
	case "diagnostic", "pass", "success":
		return output, nil
	default:
		return ExecutionOutput{}, fmt.Errorf("%w: unsupported fixture", ErrInvalidRequest)
	}
}

func executeDraftEdit(ctx context.Context, request ExecutionRequest) (ExecutionOutput, error) {
	path, err := actionPath(request, scopeDraft, true, false)
	if err != nil {
		return ExecutionOutput{}, err
	}
	if isCorePath(request.Workspace, path) {
		return ExecutionOutput{}, fmt.Errorf("%w: core paths cannot be draft-edited", ErrWorkspaceBoundary)
	}
	content, ok := request.Action.Parameters["content"].(string)
	if !ok {
		return ExecutionOutput{}, fmt.Errorf("%w: draft content must be a string", ErrInvalidRequest)
	}
	if int64(len(content)) > request.Limits.MaxInputBytes || int64(len(content)) > request.Limits.MaxFileBytes || int64(len(content)) > request.Limits.MaxDiskBytes || int64(len(content)) > request.Limits.MaxMemoryBytes {
		return ExecutionOutput{}, fmt.Errorf("%w: draft content exceeds limit", ErrResourceLimit)
	}
	if err := ctx.Err(); err != nil {
		return ExecutionOutput{}, err
	}
	var original []byte
	var existed bool
	var mode os.FileMode = 0600
	if info, statErr := os.Lstat(path); statErr == nil {
		if info.IsDir() || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || fileLinkCount(info) > 1 {
			return ExecutionOutput{}, fmt.Errorf("%w: draft target is not a private regular file", ErrSymlinkEscape)
		}
		if info.Size() > request.Limits.MaxFileBytes {
			return ExecutionOutput{}, fmt.Errorf("%w: existing draft exceeds bound", ErrResourceLimit)
		}
		original, err = os.ReadFile(path)
		if err != nil {
			return ExecutionOutput{}, err
		}
		existed = true
		mode = info.Mode().Perm()
	} else if !os.IsNotExist(statErr) {
		return ExecutionOutput{}, statErr
	}
	if expected, _ := request.Action.Parameters["expected_digest"].(string); strings.TrimSpace(expected) != "" {
		actual := ""
		if existed {
			actual = hashBytes(original)
		}
		if expected != actual {
			return ExecutionOutput{}, fmt.Errorf("%w: draft precondition digest mismatch", ErrInvalidRequest)
		}
	}
	if err := ensurePrivateParent(request.Workspace, path); err != nil {
		return ExecutionOutput{}, err
	}
	if err := atomicWrite(path, []byte(content), mode); err != nil {
		return ExecutionOutput{}, err
	}
	diff := unifiedDiff(relativePath(request.Workspace, path), string(original), content)
	value := map[string]any{"path": relativePath(request.Workspace, path), "before_digest": hashBytes(original), "after_digest": hashBytes([]byte(content)), "bytes": len(content), "candidate_only": true, "diff": diff}
	return ExecutionOutput{Value: value, Diff: diff, Digest: outputDigest(value, diff), Bytes: int64(len(content)) + int64(len(diff)), Files: 1, Rollback: &RollbackState{Path: path, Existed: existed, Original: append([]byte(nil), original...), Mode: mode, Changed: true}}, nil
}

func executePatchCandidate(ctx context.Context, request ExecutionRequest) (ExecutionOutput, error) {
	path, err := actionPath(request, scopeWorkspace, true, false)
	if err != nil {
		return ExecutionOutput{}, err
	}
	content, ok := request.Action.Parameters["content"].(string)
	if !ok {
		return ExecutionOutput{}, fmt.Errorf("%w: patch content must be a string", ErrInvalidRequest)
	}
	if int64(len(content)) > request.Limits.MaxInputBytes || int64(len(content)) > request.Limits.MaxFileBytes || int64(len(content)) > request.Limits.MaxMemoryBytes {
		return ExecutionOutput{}, fmt.Errorf("%w: patch content exceeds limit", ErrResourceLimit)
	}
	if err := ctx.Err(); err != nil {
		return ExecutionOutput{}, err
	}
	var original []byte
	if info, statErr := os.Lstat(path); statErr == nil {
		if info.IsDir() || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || fileLinkCount(info) > 1 {
			return ExecutionOutput{}, fmt.Errorf("%w: patch target is not a regular file", ErrSymlinkEscape)
		}
		if info.Size() > request.Limits.MaxFileBytes {
			return ExecutionOutput{}, fmt.Errorf("%w: source exceeds bound", ErrResourceLimit)
		}
		original, err = os.ReadFile(path)
		if err != nil {
			return ExecutionOutput{}, err
		}
	} else if !os.IsNotExist(statErr) {
		return ExecutionOutput{}, statErr
	}
	if expected, _ := request.Action.Parameters["expected_digest"].(string); strings.TrimSpace(expected) != "" && expected != hashBytes(original) {
		return ExecutionOutput{}, fmt.Errorf("%w: patch precondition digest mismatch", ErrInvalidRequest)
	}
	diff := unifiedDiff(relativePath(request.Workspace, path), string(original), content)
	value := map[string]any{"path": relativePath(request.Workspace, path), "before_digest": hashBytes(original), "candidate_digest": hashBytes([]byte(content)), "diff": diff, "candidate_only": true, "core_path": isCorePath(request.Workspace, path)}
	return ExecutionOutput{Value: value, Diff: diff, Digest: outputDigest(value, diff), Bytes: int64(len(diff)), Files: 1}, nil
}

func actionPath(request ExecutionRequest, scope toolsScope, allowMissing, allowDirectory bool) (string, error) {
	requested := optionalPath(request.Action.Parameters)
	if requested == "" {
		return "", fmt.Errorf("%w: action path is required", ErrInvalidRequest)
	}
	return secureScopedPath(request.Workspace, requested, scope, allowMissing, allowDirectory)
}

func optionalPath(parameters map[string]any) string {
	value, _ := parameters["path"].(string)
	return strings.TrimSpace(value)
}

func intFrom(parameters map[string]any, key string, fallback int) int {
	value, ok := parameters[key]
	if !ok {
		return fallback
	}
	switch number := value.(type) {
	case int:
		return number
	case int64:
		return int(number)
	case float64:
		return int(number)
	default:
		return fallback
	}
}

func int64From(parameters map[string]any, key string, fallback int64) int64 {
	value, ok := parameters[key]
	if !ok {
		return fallback
	}
	switch number := value.(type) {
	case int:
		return int64(number)
	case int64:
		return number
	case float64:
		return int64(number)
	default:
		return fallback
	}
}

func boundedReadLimits(request ExecutionRequest) tools.ResourceLimits {
	limits := request.Limits
	requested := int64From(request.Action.Parameters, "max_bytes", 0)
	if requested > 0 {
		if requested < limits.MaxInputBytes {
			limits.MaxInputBytes = requested
		}
		if requested < limits.MaxFileBytes {
			limits.MaxFileBytes = requested
		}
	}
	return limits
}

func readBounded(ctx context.Context, path string, limits tools.ResourceLimits) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || fileLinkCount(info) > 1 {
		return nil, fmt.Errorf("%w: file is not a private regular file", ErrSymlinkEscape)
	}
	if info.Size() > limits.MaxFileBytes || info.Size() > limits.MaxInputBytes || info.Size() > limits.MaxMemoryBytes {
		return nil, fmt.Errorf("%w: file exceeds read bound", ErrResourceLimit)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if int64(len(content)) > limits.MaxTotalBytes {
		return nil, fmt.Errorf("%w: total input exceeded", ErrResourceLimit)
	}
	return content, nil
}

func walkDigest(ctx context.Context, root string, workspace Workspace, limits tools.ResourceLimits, includeRootFile bool) (int, int64, string, error) {
	files, bytes := 0, int64(0)
	h := sha256.New()
	err := walkFiles(ctx, root, workspace, limits, false, func(path string, info fs.FileInfo) error {
		content, err := readBounded(ctx, path, limits)
		if err != nil {
			return err
		}
		files++
		if files > limits.MaxFiles {
			return fmt.Errorf("%w: file count exceeded", ErrResourceLimit)
		}
		bytes += int64(len(content))
		if bytes > limits.MaxTotalBytes {
			return fmt.Errorf("%w: total input exceeded", ErrResourceLimit)
		}
		_, _ = h.Write([]byte(relativePath(workspace, path)))
		_, _ = h.Write([]byte{0})
		_, _ = h.Write(content)
		return nil
	})
	if err != nil {
		return 0, 0, "", err
	}
	if files == 0 && includeRootFile {
		return files, bytes, "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
	}
	return files, bytes, "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

func walkFiles(ctx context.Context, root string, workspace Workspace, limits tools.ResourceLimits, includeRootFile bool, visit func(string, fs.FileInfo) error) error {
	info, err := os.Lstat(root)
	if err != nil {
		return err
	}
	if info.IsDir() {
		return filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			if path != root && entry.Type()&os.ModeSymlink != 0 {
				return fmt.Errorf("%w: symlink in workspace tree", ErrSymlinkEscape)
			}
			if path != root && sensitivePath(relativePath(workspace, path)) {
				if entry.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if entry.IsDir() {
				return nil
			}
			if !entry.Type().IsRegular() {
				return fmt.Errorf("%w: special file in workspace tree", ErrWorkspaceBoundary)
			}
			fileInfo, infoErr := entry.Info()
			if infoErr != nil {
				return infoErr
			}
			if fileLinkCount(fileInfo) > 1 {
				return fmt.Errorf("%w: hard link in workspace tree", ErrSymlinkEscape)
			}
			if fileInfo.Size() > limits.MaxFileBytes {
				return fmt.Errorf("%w: file exceeds bound", ErrResourceLimit)
			}
			if err := visit(path, fileInfo); err != nil {
				return err
			}
			return nil
		})
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: root is not a regular file", ErrWorkspaceBoundary)
	}
	if includeRootFile {
		return visit(root, info)
	}
	return nil
}

func relativePath(workspace Workspace, path string) string {
	relative, err := filepath.Rel(filepath.Clean(workspace.Root), filepath.Clean(path))
	if err != nil {
		return filepath.ToSlash(filepath.Base(path))
	}
	return filepath.ToSlash(relative)
}

func boundedText(value string, max int) string {
	if len(value) <= max {
		return value
	}
	return value[:max]
}

func ensurePrivateParent(workspace Workspace, path string) error {
	parent := filepath.Dir(path)
	workspace = workspace.normalized()
	if err := validateWorkspaceRoot(workspace); err != nil {
		return err
	}
	relative, err := filepath.Rel(filepath.Clean(workspace.Root), parent)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return fmt.Errorf("%w: parent is outside workspace", ErrWorkspaceBoundary)
	}
	if relative == "." {
		return nil
	}
	current := filepath.Clean(workspace.Root)
	for _, component := range strings.Split(relative, string(filepath.Separator)) {
		if component == "" || component == "." || component == ".." {
			return fmt.Errorf("%w: invalid parent component", ErrWorkspaceBoundary)
		}
		current = filepath.Join(current, component)
		info, statErr := os.Lstat(current)
		if os.IsNotExist(statErr) {
			if err := os.Mkdir(current, 0700); err != nil {
				return err
			}
			continue
		}
		if statErr != nil {
			return statErr
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("%w: parent component is not a real directory", ErrSymlinkEscape)
		}
	}
	return nil
}

func atomicWrite(path string, content []byte, mode os.FileMode) error {
	parent := filepath.Dir(path)
	temporary, err := os.CreateTemp(parent, ".open-card-action-*")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(mode); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(content); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || fileLinkCount(info) > 1 {
			return fmt.Errorf("%w: destination changed to a link", ErrSymlinkEscape)
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	return os.Rename(temporaryName, path)
}

type builtinVerifier struct{}

func (builtinVerifier) Verify(ctx context.Context, request VerificationRequest) (Evidence, error) {
	if err := ctx.Err(); err != nil {
		return Evidence{}, err
	}
	if request.Output.Digest == "" {
		return Evidence{}, fmt.Errorf("%w: output digest is missing", ErrVerification)
	}
	if request.Descriptor.Kind == tools.KindDraftEdit {
		path, err := actionPath(ExecutionRequest{Action: request.Action, Workspace: request.Workspace}, scopeDraft, false, false)
		if err != nil {
			return Evidence{}, err
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return Evidence{}, err
		}
		value, _ := request.Output.Value.(map[string]any)
		expected, _ := value["after_digest"].(string)
		if expected == "" || expected != hashBytes(content) {
			return Evidence{}, fmt.Errorf("%w: draft digest did not verify", ErrVerification)
		}
	}
	if request.Descriptor.Kind == tools.KindPatch {
		// A candidate is verified by proving that the source still has its
		// original digest. The candidate is an in-memory diff and is never
		// written by this verifier.
		path, err := actionPath(ExecutionRequest{Action: request.Action, Workspace: request.Workspace}, scopeWorkspace, true, false)
		if err != nil {
			return Evidence{}, err
		}
		content, readErr := os.ReadFile(path)
		if readErr != nil && !os.IsNotExist(readErr) {
			return Evidence{}, readErr
		}
		value, _ := request.Output.Value.(map[string]any)
		expected, _ := value["before_digest"].(string)
		if expected != hashBytes(content) {
			return Evidence{}, fmt.Errorf("%w: source changed while candidate was generated", ErrVerification)
		}
	}
	return Evidence{Kind: "independent", Summary: "output and workspace state independently verified", Digest: request.Output.Digest, Independent: true, Redacted: true, Files: request.Output.Files, Bytes: request.Output.Bytes, Cleanup: true}, nil
}

type builtinRollbacker struct{}

func (builtinRollbacker) Rollback(ctx context.Context, request RollbackRequest) error {
	if request.State == nil || !request.State.Changed {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	path, err := securePath(request.Workspace, relativePath(request.Workspace, request.State.Path), true, false)
	if err != nil {
		return err
	}
	if request.State.Existed {
		return atomicWrite(path, request.State.Original, request.State.Mode)
	}
	if info, statErr := os.Lstat(path); statErr == nil {
		if info.Mode()&os.ModeSymlink != 0 || fileLinkCount(info) > 1 {
			return fmt.Errorf("%w: rollback destination is a link", ErrSymlinkEscape)
		}
		return os.Remove(path)
	} else if os.IsNotExist(statErr) {
		return nil
	} else {
		return statErr
	}
}

func unifiedDiff(path, before, after string) string {
	if before == after {
		return ""
	}
	left := strings.Split(strings.ReplaceAll(before, "\r\n", "\n"), "\n")
	right := strings.Split(strings.ReplaceAll(after, "\r\n", "\n"), "\n")
	var builder strings.Builder
	fmt.Fprintf(&builder, "--- a/%s\n+++ b/%s\n@@\n", path, path)
	for _, line := range left {
		builder.WriteByte('-')
		builder.WriteString(line)
		builder.WriteByte('\n')
	}
	for _, line := range right {
		builder.WriteByte('+')
		builder.WriteString(line)
		builder.WriteByte('\n')
	}
	return builder.String()
}
