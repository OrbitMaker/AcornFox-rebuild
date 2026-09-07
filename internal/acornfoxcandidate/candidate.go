// Package acornfoxcandidate creates unpublished application-source candidates.
// A candidate is derived from an immutable public Git SourceRevision, but it
// never acquires or claims a Git commit of its own.
package acornfoxcandidate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/open-card/open-card/internal/domain"
	"github.com/open-card/open-card/internal/foundation"
)

const (
	MaxPatchBytes     = 128 << 10
	MaxChangedFiles   = 32
	MaxContextBytes   = 64 << 10
	MaxContextFile    = 16 << 10
	MaxCandidateFiles = 100_000
	MaxCandidateBytes = int64(2 << 30)
)

var (
	ErrInvalidBase      = errors.New("candidate base source is invalid")
	ErrUnsafePath       = errors.New("candidate path is unsafe")
	ErrInvalidPatch     = errors.New("candidate patch is invalid")
	ErrCandidateChanged = errors.New("candidate workspace changed")
	ErrCandidateLimit   = errors.New("candidate resource limit exceeded")
)

type SourceFile struct {
	Path    string `json:"path"`
	Content string `json:"content"`
	Digest  string `json:"digest"`
	Bytes   int    `json:"bytes"`
}

type ReadResult struct {
	BaseSourceRevisionID domain.ID    `json:"base_source_revision_id"`
	BaseCommit           string       `json:"base_commit"`
	BaseTreeDigest       string       `json:"base_tree_digest"`
	Files                []SourceFile `json:"files"`
	TotalBytes           int          `json:"total_bytes"`
}

type Snapshot struct {
	ID                   domain.ID `json:"candidate_id"`
	ApplicationID        domain.ID `json:"application_id"`
	BaseSourceRevisionID domain.ID `json:"base_source_revision_id"`
	BaseRepositoryURL    string    `json:"base_repository_url"`
	BaseCommit           string    `json:"base_commit"`
	BaseTreeDigest       string    `json:"base_tree_digest"`
	PatchDigest          string    `json:"patch_digest"`
	TreeDigest           string    `json:"tree_digest"`
	ChangedPaths         []string  `json:"changed_paths"`
	CanonicalDiff        []byte    `json:"-"`
	WorkspaceRef         string    `json:"-"`
	CreatedAt            time.Time `json:"created_at"`
	ExpiresAt            time.Time `json:"expires_at"`
}

func (s Snapshot) Validate() error {
	if domain.RequireID(s.ID, "candidate id") != nil || domain.RequireID(s.ApplicationID, "application id") != nil || domain.RequireID(s.BaseSourceRevisionID, "base source revision id") != nil || s.BaseRepositoryURL == "" || !validCommit(s.BaseCommit) || !validDigest(s.BaseTreeDigest) || !validDigest(s.PatchDigest) || !validDigest(s.TreeDigest) || s.BaseTreeDigest == s.TreeDigest || len(s.ChangedPaths) < 1 || len(s.ChangedPaths) > MaxChangedFiles || len(s.CanonicalDiff) == 0 || len(s.CanonicalDiff) > MaxPatchBytes || s.WorkspaceRef == "" || s.CreatedAt.IsZero() || !s.ExpiresAt.After(s.CreatedAt) {
		return ErrCandidateChanged
	}
	for index, path := range s.ChangedPaths {
		if safeRelativePath(path) != nil || index > 0 && s.ChangedPaths[index-1] >= path {
			return ErrCandidateChanged
		}
	}
	return nil
}

// TransientSource adapts a sealed candidate to the existing BuildProvider.
// SourceUpload is intentional: it carries no Git commit and is never persisted
// as a SourceRevision or passed to the normal delivery store.
func (s Snapshot) TransientSource() (domain.SourceRevision, error) {
	if err := s.Validate(); err != nil {
		return domain.SourceRevision{}, err
	}
	revision := domain.SourceRevision{
		ID: s.ID, ApplicationID: s.ApplicationID, Kind: domain.SourceUpload,
		Locator: "candidate://" + s.ID.String(), ContentDigest: s.TreeDigest,
		WorkspaceRef: s.WorkspaceRef, CreatedAt: s.CreatedAt.UTC(), Immutable: true,
	}
	if err := revision.Validate(); err != nil || revision.Commit != "" {
		return domain.SourceRevision{}, ErrCandidateChanged
	}
	return revision, nil
}

type Manager struct {
	workspaceRoot string
	candidateRoot string
	gitBinary     string
	gitDigest     string
	clock         func() time.Time
}

func NewManager(workspaceRoot string) (*Manager, error) {
	root, err := secureExistingRoot(workspaceRoot)
	if err != nil {
		return nil, err
	}
	gitBinary := "/usr/bin/git"
	gitDigest, err := digestRegularFile(gitBinary)
	if err != nil {
		return nil, fmt.Errorf("candidate Git executable is unavailable")
	}
	candidateRoot := filepath.Join(root, ".acornfox-candidates")
	if err := os.Mkdir(candidateRoot, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return nil, err
	}
	info, err := os.Lstat(candidateRoot)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("candidate workspace root is unsafe")
	}
	entries, err := os.ReadDir(candidateRoot)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		name := entry.Name()
		owned := strings.HasPrefix(name, ".stage-") || strings.HasPrefix(name, "candidate_") && len(name) == len("candidate_")+32
		if !owned {
			continue
		}
		path := filepath.Join(candidateRoot, name)
		info, err := os.Lstat(path)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || removeCandidateTree(path) != nil {
			return nil, errors.New("candidate staging recovery failed")
		}
	}
	return &Manager{workspaceRoot: root, candidateRoot: candidateRoot, gitBinary: gitBinary, gitDigest: gitDigest, clock: time.Now}, nil
}

func (m *Manager) Read(ctx context.Context, base domain.SourceRevision, paths []string) (ReadResult, error) {
	baseRoot, err := m.verifyBase(base)
	if err != nil {
		return ReadResult{}, err
	}
	if len(paths) < 1 || len(paths) > MaxChangedFiles {
		return ReadResult{}, ErrCandidateLimit
	}
	unique := map[string]bool{}
	normalized := make([]string, 0, len(paths))
	for _, path := range paths {
		if err := safeRelativePath(path); err != nil || unique[path] {
			return ReadResult{}, ErrUnsafePath
		}
		unique[path] = true
		normalized = append(normalized, path)
	}
	sort.Strings(normalized)
	snapshotRoot, err := os.MkdirTemp(m.candidateRoot, ".stage-read-")
	if err != nil {
		return ReadResult{}, err
	}
	defer removeCandidateTree(snapshotRoot)
	if err := copyCandidateTree(ctx, baseRoot, snapshotRoot); err != nil {
		return ReadResult{}, err
	}
	if digest, err := foundation.HashDirectory(snapshotRoot); err != nil || "sha256:"+digest != base.ContentDigest {
		return ReadResult{}, ErrInvalidBase
	}
	result := ReadResult{BaseSourceRevisionID: base.ID, BaseCommit: base.Commit, BaseTreeDigest: base.ContentDigest, Files: make([]SourceFile, 0, len(normalized))}
	for _, path := range normalized {
		if err := ctx.Err(); err != nil {
			return ReadResult{}, err
		}
		filePath := filepath.Join(snapshotRoot, filepath.FromSlash(path))
		if !within(snapshotRoot, filePath) {
			return ReadResult{}, ErrUnsafePath
		}
		info, err := os.Lstat(filePath)
		if err != nil || !singleRegular(info) || info.Size() > MaxContextFile {
			return ReadResult{}, ErrCandidateLimit
		}
		content, err := os.ReadFile(filePath)
		if err != nil {
			return ReadResult{}, fmt.Errorf("%w: read source file", ErrInvalidBase)
		}
		if !utf8.Valid(content) || bytes.IndexByte(content, 0) >= 0 {
			return ReadResult{}, fmt.Errorf("%w: source file is not ordinary text", ErrInvalidBase)
		}
		result.TotalBytes += len(content)
		if result.TotalBytes > MaxContextBytes {
			return ReadResult{}, ErrCandidateLimit
		}
		result.Files = append(result.Files, SourceFile{Path: path, Content: string(content), Digest: digestBytes(content), Bytes: len(content)})
	}
	return result, nil
}

func (m *Manager) Apply(ctx context.Context, base domain.SourceRevision, repositoryURL string, patch []byte, lifetime time.Duration) (Snapshot, error) {
	id, err := domain.NewID("candidate")
	if err != nil {
		return Snapshot{}, err
	}
	return m.ApplyFor(ctx, id, base, repositoryURL, patch, lifetime)
}

// ApplyFor creates a sealed candidate using an identity that was durably
// reserved before the potentially long build and runtime validation phases.
func (m *Manager) ApplyFor(ctx context.Context, id domain.ID, base domain.SourceRevision, repositoryURL string, patch []byte, lifetime time.Duration) (Snapshot, error) {
	if m == nil || lifetime <= 0 || len(patch) == 0 || len(patch) > MaxPatchBytes || !utf8.Valid(patch) || bytes.IndexByte(patch, 0) >= 0 {
		return Snapshot{}, ErrInvalidPatch
	}
	if !validCandidateID(id) {
		return Snapshot{}, ErrInvalidPatch
	}
	baseRoot, err := m.verifyBase(base)
	if err != nil {
		return Snapshot{}, err
	}
	canonical, changed, err := validatePatch(patch)
	if err != nil {
		return Snapshot{}, err
	}
	stage, err := os.MkdirTemp(m.candidateRoot, ".stage-")
	if err != nil {
		return Snapshot{}, err
	}
	success := false
	defer func() {
		if !success {
			_ = removeCandidateTree(stage)
		}
	}()
	if err := os.Chmod(stage, 0o700); err != nil {
		return Snapshot{}, err
	}
	if err := copyCandidateTree(ctx, baseRoot, stage); err != nil {
		return Snapshot{}, err
	}
	if digest, err := foundation.HashDirectory(stage); err != nil || "sha256:"+digest != base.ContentDigest {
		return Snapshot{}, ErrInvalidBase
	}
	originals := make(map[string][]byte, len(changed))
	originalModes := make(map[string]bool, len(changed))
	for _, path := range changed {
		candidatePath := filepath.Join(stage, filepath.FromSlash(path))
		value, err := os.ReadFile(candidatePath)
		if err != nil || !utf8.Valid(value) || bytes.IndexByte(value, 0) >= 0 {
			return Snapshot{}, ErrInvalidPatch
		}
		originals[path] = value
		info, err := os.Lstat(candidatePath)
		if err != nil || !singleRegular(info) {
			return Snapshot{}, ErrInvalidPatch
		}
		originalModes[path] = info.Mode().Perm()&0o111 != 0
	}
	if err := m.runGitApply(ctx, stage, canonical, true); err != nil {
		return Snapshot{}, err
	}
	if err := m.runGitApply(ctx, stage, canonical, false); err != nil {
		return Snapshot{}, err
	}
	if err := sameCandidateModes(stage, originalModes, changed); err != nil {
		return Snapshot{}, err
	}
	canonical, err = canonicalCandidateDiff(stage, originals, changed)
	if err != nil {
		return Snapshot{}, err
	}
	if err := verifyCandidateTree(stage); err != nil {
		return Snapshot{}, err
	}
	tree, err := foundation.HashDirectory(stage)
	if err != nil {
		return Snapshot{}, ErrCandidateChanged
	}
	treeDigest := "sha256:" + tree
	if treeDigest == base.ContentDigest {
		return Snapshot{}, ErrInvalidPatch
	}
	patchDigest := digestBytes(canonical)
	final := filepath.Join(m.candidateRoot, id.String())
	if _, err := os.Lstat(final); !errors.Is(err, fs.ErrNotExist) {
		return Snapshot{}, ErrCandidateChanged
	}
	if err := makeCandidateReadOnly(stage); err != nil {
		return Snapshot{}, err
	}
	if err := os.Rename(stage, final); err != nil {
		return Snapshot{}, err
	}
	success = true
	now := m.clock().UTC()
	snapshot := Snapshot{
		ID: id, ApplicationID: base.ApplicationID, BaseSourceRevisionID: base.ID,
		BaseRepositoryURL: repositoryURL, BaseCommit: base.Commit, BaseTreeDigest: base.ContentDigest,
		PatchDigest: patchDigest, TreeDigest: treeDigest, ChangedPaths: changed,
		CanonicalDiff: append([]byte(nil), canonical...), WorkspaceRef: final,
		CreatedAt: now, ExpiresAt: now.Add(lifetime),
	}
	if err := snapshot.Validate(); err != nil {
		_ = removeCandidateTree(final)
		return Snapshot{}, err
	}
	return snapshot, nil
}

func validCandidateID(id domain.ID) bool {
	value := id.String()
	if len(value) != len("candidate_")+32 || !strings.HasPrefix(value, "candidate_") {
		return false
	}
	for _, character := range value[len("candidate_"):] {
		if !(character >= '0' && character <= '9' || character >= 'a' && character <= 'f') {
			return false
		}
	}
	return true
}

func (m *Manager) Verify(snapshot Snapshot) error {
	if m == nil || snapshot.Validate() != nil || !within(m.candidateRoot, snapshot.WorkspaceRef) {
		return ErrCandidateChanged
	}
	digest, err := foundation.HashDirectory(snapshot.WorkspaceRef)
	if err != nil || "sha256:"+digest != snapshot.TreeDigest {
		return ErrCandidateChanged
	}
	currentGit, err := digestRegularFile(m.gitBinary)
	if err != nil || currentGit != m.gitDigest {
		return ErrCandidateChanged
	}
	return nil
}

func (m *Manager) Release(snapshot Snapshot) error {
	if m == nil || snapshot.ID.Empty() || filepath.Clean(snapshot.WorkspaceRef) != filepath.Join(m.candidateRoot, snapshot.ID.String()) || !within(m.candidateRoot, snapshot.WorkspaceRef) {
		return ErrCandidateChanged
	}
	return removeCandidateTree(snapshot.WorkspaceRef)
}

func (m *Manager) verifyBase(base domain.SourceRevision) (string, error) {
	if m == nil {
		return "", ErrInvalidBase
	}
	if err := base.Validate(); err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalidBase, err)
	}
	if base.Kind != domain.SourceGitHTTPS || base.Commit == "" || !validDigest(base.ContentDigest) {
		return "", fmt.Errorf("%w: source identity", ErrInvalidBase)
	}
	root, err := filepath.EvalSymlinks(base.WorkspaceRef)
	if err != nil || !within(m.workspaceRoot, root) || within(m.candidateRoot, root) {
		return "", fmt.Errorf("%w: workspace boundary", ErrInvalidBase)
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", ErrInvalidBase
	}
	digest, err := foundation.HashDirectory(root)
	if err != nil || "sha256:"+digest != base.ContentDigest {
		return "", fmt.Errorf("%w: tree digest", ErrInvalidBase)
	}
	return root, nil
}

func (m *Manager) runGitApply(ctx context.Context, root string, patch []byte, check bool) error {
	if current, err := digestRegularFile(m.gitBinary); err != nil || current != m.gitDigest {
		return ErrCandidateChanged
	}
	args := []string{"-C", root, "-c", "credential.helper=", "-c", "core.hooksPath=/dev/null", "-c", "protocol.file.allow=never", "apply", "--whitespace=error-all", "-p1"}
	if check {
		args = append(args, "--check")
	}
	command := exec.CommandContext(ctx, m.gitBinary, args...)
	command.Env = candidateGitEnvironment()
	command.Stdin = bytes.NewReader(patch)
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	output := &boundedBuffer{limit: 16 << 10}
	command.Stdout, command.Stderr = output, output
	if err := command.Start(); err != nil {
		return ErrInvalidPatch
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	select {
	case err := <-done:
		if err != nil || output.exceeded {
			return ErrInvalidPatch
		}
	case <-ctx.Done():
		if command.Process != nil {
			_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		}
		<-done
		return ctx.Err()
	}
	if current, err := digestRegularFile(m.gitBinary); err != nil || current != m.gitDigest {
		return ErrCandidateChanged
	}
	return nil
}

type boundedBuffer struct {
	bytes.Buffer
	limit    int
	exceeded bool
}

func (b *boundedBuffer) Write(value []byte) (int, error) {
	if len(value) > b.limit-b.Len() {
		remaining := b.limit - b.Len()
		if remaining > 0 {
			_, _ = b.Buffer.Write(value[:remaining])
		}
		b.exceeded = true
		return len(value), nil
	}
	return b.Buffer.Write(value)
}

func validatePatch(raw []byte) ([]byte, []string, error) {
	if bytes.Contains(raw, []byte("\r")) || raw[len(raw)-1] != '\n' {
		return nil, nil, ErrInvalidPatch
	}
	lines := strings.Split(string(raw), "\n")
	changed := map[string]bool{}
	var current string
	seenOld, seenNew, seenHunk := false, false, false
	finish := func() error {
		if current != "" && (!seenOld || !seenNew || !seenHunk) {
			return ErrInvalidPatch
		}
		return nil
	}
	for _, line := range lines[:len(lines)-1] {
		switch {
		case strings.HasPrefix(line, "diff --git "):
			if err := finish(); err != nil {
				return nil, nil, err
			}
			fields := strings.Fields(line)
			if len(fields) != 4 || !strings.HasPrefix(fields[2], "a/") || !strings.HasPrefix(fields[3], "b/") {
				return nil, nil, ErrInvalidPatch
			}
			oldPath, newPath := strings.TrimPrefix(fields[2], "a/"), strings.TrimPrefix(fields[3], "b/")
			if oldPath != newPath || safeRelativePath(oldPath) != nil || changed[oldPath] {
				return nil, nil, ErrUnsafePath
			}
			current, changed[oldPath] = oldPath, true
			seenOld, seenNew, seenHunk = false, false, false
		case current == "":
			return nil, nil, ErrInvalidPatch
		case strings.HasPrefix(line, "--- "):
			if line != "--- a/"+current || seenOld {
				return nil, nil, ErrInvalidPatch
			}
			seenOld = true
		case strings.HasPrefix(line, "+++ "):
			if line != "+++ b/"+current || !seenOld || seenNew {
				return nil, nil, ErrInvalidPatch
			}
			seenNew = true
		case strings.HasPrefix(line, "@@ "):
			if !seenOld || !seenNew {
				return nil, nil, ErrInvalidPatch
			}
			seenHunk = true
		case strings.HasPrefix(line, "index "):
			fields := strings.Fields(line)
			if seenOld || len(fields) < 2 || len(fields) > 3 || !strings.Contains(fields[1], "..") || len(fields) == 3 && fields[2] != "100644" && fields[2] != "100755" {
				return nil, nil, ErrInvalidPatch
			}
		case strings.HasPrefix(line, " "), strings.HasPrefix(line, "+"), strings.HasPrefix(line, "-"), line == `\ No newline at end of file`:
			if !seenHunk {
				return nil, nil, ErrInvalidPatch
			}
		default:
			return nil, nil, ErrInvalidPatch
		}
	}
	if err := finish(); err != nil || len(changed) == 0 || len(changed) > MaxChangedFiles {
		return nil, nil, ErrInvalidPatch
	}
	paths := make([]string, 0, len(changed))
	for path := range changed {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	return append([]byte(nil), raw...), paths, nil
}

func safeRelativePath(value string) error {
	if value == "" || filepath.IsAbs(value) || strings.ContainsAny(value, "\x00\\\r\n") || filepath.ToSlash(filepath.Clean(value)) != value || value == "." || value == ".." || strings.HasPrefix(value, "../") {
		return ErrUnsafePath
	}
	for _, part := range strings.Split(strings.ToLower(value), "/") {
		if part == ".git" || part == "secrets" || part == "credentials" {
			return ErrUnsafePath
		}
	}
	base := strings.ToLower(filepath.Base(value))
	if base == ".env" || strings.HasPrefix(base, ".env.") || base == "credentials" || base == "credentials.json" || base == "secret.json" || base == "id_rsa" || base == "id_ed25519" {
		return ErrUnsafePath
	}
	for _, suffix := range []string{".pem", ".key", ".p12", ".pfx", ".jks", ".token"} {
		if strings.HasSuffix(base, suffix) {
			return ErrUnsafePath
		}
	}
	return nil
}

func copyCandidateTree(ctx context.Context, source, destination string) error {
	sourceRoot, err := os.OpenRoot(source)
	if err != nil {
		return ErrInvalidBase
	}
	defer sourceRoot.Close()
	destinationRoot, err := os.OpenRoot(destination)
	if err != nil {
		return err
	}
	defer destinationRoot.Close()
	files, bytes := 0, int64(0)
	return copyCandidateDirectory(ctx, sourceRoot, destinationRoot, &files, &bytes)
}

func copyCandidateDirectory(ctx context.Context, source, destination *os.Root, files *int, bytes *int64) error {
	entries, err := fs.ReadDir(source.FS(), ".")
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		name := entry.Name()
		if name == "." || name == ".." || strings.ContainsAny(name, "/\\\x00") {
			return ErrInvalidBase
		}
		before, err := source.Lstat(name)
		if err != nil || before.Mode()&os.ModeSymlink != 0 {
			return ErrInvalidBase
		}
		if before.IsDir() {
			if err := destination.Mkdir(name, 0o700); err != nil {
				return err
			}
			sourceChild, err := source.OpenRoot(name)
			if err != nil {
				return ErrInvalidBase
			}
			after, statErr := sourceChild.Stat(".")
			if statErr != nil || !os.SameFile(before, after) {
				sourceChild.Close()
				return ErrInvalidBase
			}
			destinationChild, err := destination.OpenRoot(name)
			if err != nil {
				sourceChild.Close()
				return err
			}
			err = copyCandidateDirectory(ctx, sourceChild, destinationChild, files, bytes)
			destinationChild.Close()
			sourceChild.Close()
			if err != nil {
				return err
			}
			continue
		}
		if !singleRegular(before) {
			return ErrInvalidBase
		}
		input, err := source.Open(name)
		if err != nil {
			return ErrInvalidBase
		}
		after, statErr := input.Stat()
		if statErr != nil || !os.SameFile(before, after) || !singleRegular(after) {
			input.Close()
			return ErrInvalidBase
		}
		*files = *files + 1
		*bytes += after.Size()
		if *files > MaxCandidateFiles || *bytes > MaxCandidateBytes {
			input.Close()
			return ErrCandidateLimit
		}
		mode := os.FileMode(0o600)
		if after.Mode().Perm()&0o111 != 0 {
			mode = 0o700
		}
		output, err := destination.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
		if err != nil {
			input.Close()
			return err
		}
		written, copyErr := io.Copy(output, io.LimitReader(input, after.Size()+1))
		closeOutput, closeInput := output.Close(), input.Close()
		if copyErr != nil || closeOutput != nil || closeInput != nil || written != after.Size() {
			return ErrInvalidBase
		}
	}
	return nil
}

func verifyCandidateTree(root string) error {
	files, bytes := 0, int64(0)
	return filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == root {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return ErrCandidateChanged
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil || !singleRegular(info) {
			return ErrCandidateChanged
		}
		files++
		bytes += info.Size()
		if files > MaxCandidateFiles || bytes > MaxCandidateBytes {
			return ErrCandidateLimit
		}
		return nil
	})
}

func sameCandidateModes(candidateRoot string, executable map[string]bool, paths []string) error {
	for _, path := range paths {
		candidate, candidateErr := os.Lstat(filepath.Join(candidateRoot, filepath.FromSlash(path)))
		if candidateErr != nil || !singleRegular(candidate) || executable[path] != (candidate.Mode().Perm()&0o111 != 0) {
			return ErrInvalidPatch
		}
	}
	return nil
}

func canonicalCandidateDiff(candidateRoot string, originals map[string][]byte, paths []string) ([]byte, error) {
	var output bytes.Buffer
	for _, path := range paths {
		before, ok := originals[path]
		after, err := os.ReadFile(filepath.Join(candidateRoot, filepath.FromSlash(path)))
		if !ok || err != nil || !utf8.Valid(after) || bytes.IndexByte(after, 0) >= 0 || bytes.Equal(before, after) {
			return nil, ErrInvalidPatch
		}
		beforeLines, beforeNewline := candidateDiffLines(before)
		afterLines, afterNewline := candidateDiffLines(after)
		fmt.Fprintf(&output, "diff --git a/%s b/%s\n--- a/%s\n+++ b/%s\n@@ -%s +%s @@\n", path, path, path, path, candidateDiffRange(len(beforeLines)), candidateDiffRange(len(afterLines)))
		for index, line := range beforeLines {
			output.WriteByte('-')
			output.WriteString(line)
			output.WriteByte('\n')
			if index == len(beforeLines)-1 && !beforeNewline {
				output.WriteString("\\ No newline at end of file\n")
			}
		}
		for index, line := range afterLines {
			output.WriteByte('+')
			output.WriteString(line)
			output.WriteByte('\n')
			if index == len(afterLines)-1 && !afterNewline {
				output.WriteString("\\ No newline at end of file\n")
			}
		}
		if output.Len() > MaxPatchBytes {
			return nil, ErrCandidateLimit
		}
	}
	return output.Bytes(), nil
}

func candidateDiffLines(value []byte) ([]string, bool) {
	newline := len(value) > 0 && value[len(value)-1] == '\n'
	text := string(value)
	if newline {
		text = strings.TrimSuffix(text, "\n")
	}
	if text == "" {
		return nil, newline
	}
	return strings.Split(text, "\n"), newline
}

func candidateDiffRange(lines int) string {
	if lines == 0 {
		return "0,0"
	}
	if lines == 1 {
		return "1"
	}
	return fmt.Sprintf("1,%d", lines)
}

func makeCandidateReadOnly(root string) error {
	paths := make([]string, 0)
	if err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		paths = append(paths, path)
		return nil
	}); err != nil {
		return err
	}
	for index := len(paths) - 1; index >= 0; index-- {
		info, err := os.Lstat(paths[index])
		if err != nil {
			return err
		}
		mode := os.FileMode(0o444)
		if info.IsDir() {
			mode = 0o555
		} else if info.Mode().Perm()&0o111 != 0 {
			mode = 0o555
		}
		if err := os.Chmod(paths[index], mode); err != nil {
			return err
		}
	}
	return nil
}

func removeCandidateTree(root string) error {
	_ = filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err == nil {
			if entry.IsDir() {
				_ = os.Chmod(path, 0o700)
			} else {
				_ = os.Chmod(path, 0o600)
			}
		}
		return nil
	})
	return os.RemoveAll(root)
}

func secureExistingRoot(value string) (string, error) {
	if value == "" || !filepath.IsAbs(value) || filepath.Clean(value) != value || value == string(filepath.Separator) {
		return "", ErrInvalidBase
	}
	resolved, err := filepath.EvalSymlinks(value)
	original, originalErr := os.Lstat(value)
	info, statErr := os.Lstat(resolved)
	if err != nil || originalErr != nil || statErr != nil || original.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || resolved == string(filepath.Separator) {
		return "", ErrInvalidBase
	}
	return resolved, nil
}

func within(root, path string) bool {
	relative, err := filepath.Rel(filepath.Clean(root), filepath.Clean(path))
	return err == nil && relative != "." && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) && !filepath.IsAbs(relative)
}

func singleRegular(info fs.FileInfo) bool {
	if info == nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return false
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok && stat.Nlink != 1 {
		return false
	}
	return true
}

func digestRegularFile(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return "", ErrCandidateChanged
	}
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	hash := sha256.New()
	_, copyErr := io.Copy(hash, file)
	closeErr := file.Close()
	if copyErr != nil || closeErr != nil {
		return "", ErrCandidateChanged
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}

func digestBytes(value []byte) string {
	digest := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func validDigest(value string) bool {
	if len(value) != 71 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	_, err := hex.DecodeString(value[7:])
	return err == nil && strings.ToLower(value) == value
}

func validCommit(value string) bool {
	if len(value) != 40 && len(value) != 64 {
		return false
	}
	for _, character := range value {
		if !(character >= '0' && character <= '9' || character >= 'a' && character <= 'f') {
			return false
		}
	}
	return true
}

func candidateGitEnvironment() []string {
	return []string{
		"PATH=/usr/bin:/bin",
		"HOME=" + os.TempDir(),
		"LC_ALL=C", "LANG=C",
		"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_ATTR_NOSYSTEM=1",
		"GIT_TERMINAL_PROMPT=0", "GIT_ASKPASS=/bin/false", "GCM_INTERACTIVE=Never",
		"GIT_LFS_SKIP_SMUDGE=1", "GIT_OPTIONAL_LOCKS=0", "GIT_CONFIG_COUNT=0",
	}
}
