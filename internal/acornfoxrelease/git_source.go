package acornfoxrelease

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var ErrGitSource = errors.New("acornfox git source is invalid")

type commandRunner = goCommandRunner

type commandExitError struct {
	code int
	err  error
}

func (e *commandExitError) Error() string { return e.err.Error() }
func (e *commandExitError) Unwrap() error { return e.err }

func localCommand(ctx context.Context, name string, args []string, dir string, env []string) ([]byte, error) {
	c := exec.CommandContext(ctx, name, args...)
	c.Dir = dir
	path := os.Getenv("PATH")
	lang := os.Getenv("LANG")
	c.Env = append([]string{"PATH=" + path, "LANG=" + lang, "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_TERMINAL_PROMPT=0", "GIT_OPTIONAL_LOCKS=0", "GIT_NO_REPLACE_OBJECTS=1"}, env...)
	var output cappedBuffer
	output.limit = maxGoListBytes
	c.Stdout = &output
	c.Stderr = io.Discard
	if err := c.Run(); err != nil || output.exceeded {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return nil, &commandExitError{code: exit.ExitCode(), err: err}
		}
		return nil, ErrGitSource
	}
	return output.Bytes(), nil
}

// VerifyGitSourceV1 runs local read-only Git inspection only. A configured
// local origin is bound to the decision but is never evidence of publication.
func VerifyGitSourceV1(ctx context.Context, root string, witness Witness, policy SourcePolicyV1, toolchain ToolchainInputsV1) error {
	return verifyGitSource(ctx, root, witness, policy, toolchain, localCommand)
}
func verifyGitSource(ctx context.Context, root string, witness Witness, policy SourcePolicyV1, toolchain ToolchainInputsV1, run commandRunner) error {
	return verifyGitSourceWithDependencies(ctx, root, witness, policy, toolchain, run, exec.LookPath, hashTrustedExecutable)
}
func verifyGitSourceWithDependencies(ctx context.Context, root string, witness Witness, policy SourcePolicyV1, toolchain ToolchainInputsV1, run commandRunner, lookup executableResolver, hash executableHasher) error {
	if !witness.Valid() {
		return ErrGitSource
	}
	return verifyGitSourceIdentity(ctx, root, sourceIdentityFromWitness(witness), policy, toolchain, run, lookup, hash)
}

func verifyGitSourceIdentity(ctx context.Context, root string, identity sourceIdentity, policy SourcePolicyV1, toolchain ToolchainInputsV1, run commandRunner, lookup executableResolver, hash executableHasher) error {
	canonical, canonicalErr := CanonicalSourcePolicyV1(policy)
	toolchainRaw, toolchainErr := CanonicalToolchainInputsV1(toolchain)
	root, rootErr := cleanGitRoot(root)
	if ctx == nil || ctx.Err() != nil || run == nil || lookup == nil || hash == nil || rootErr != nil || !identity.valid() || canonicalErr != nil || toolchainErr != nil || sha256Text(canonical) != identity.policySHA || sha256Text(toolchainRaw) != identity.toolchainSHA {
		return ErrGitSource
	}
	git, err := bindExecutable("git", toolchain.GitBinarySHA256, run, lookup, hash)
	if err != nil {
		return ErrGitSource
	}
	version, err := git.Run(ctx, gitReadArgs("--version"), root, gitReadEnv())
	if err != nil || gitVersionFromOutput(version) != toolchain.GitVersion {
		return ErrGitSource
	}
	call := func(args ...string) (string, error) {
		raw, e := git.Run(ctx, gitReadArgs(args...), root, gitReadEnv())
		return strings.TrimSpace(string(raw)), e
	}
	top, e := call("rev-parse", "--show-toplevel")
	top, topErr := cleanGitRoot(top)
	if e != nil || topErr != nil || top != root {
		return ErrGitSource
	}
	commit, e := call("rev-parse", "HEAD^{commit}")
	if e != nil || commit != identity.commit {
		return ErrGitSource
	}
	if _, e = call("symbolic-ref", "-q", "HEAD"); !hasExitCode(e, 1) {
		return ErrGitSource
	}
	status, e := call("status", "--porcelain=v1", "-z", "--untracked-files=all", "--ignore-submodules=none", "--no-ahead-behind")
	if e != nil || status != "" {
		return ErrGitSource
	}
	remotes, e := call("remote")
	if e != nil || remotes != "origin" {
		return ErrGitSource
	}
	origin, e := call("remote", "get-url", "--all", "origin")
	if e != nil || !onlyExpectedRemoteURL(origin, identity.repository) {
		return ErrGitSource
	}
	pushOrigin, e := call("remote", "get-url", "--push", "--all", "origin")
	if e != nil || !onlyExpectedRemoteURL(pushOrigin, identity.repository) {
		return ErrGitSource
	}
	raw, e := git.Run(ctx, gitReadArgs("ls-files", "-z", "--stage"), root, gitReadEnv())
	if e != nil {
		return ErrGitSource
	}
	tree, e := git.Run(ctx, gitReadArgs("ls-tree", "-r", "-z", identity.commit), root, gitReadEnv())
	if e != nil || !gitIndexMatches(raw, tree, policy.Files, ctx, root, git) {
		return ErrGitSource
	}
	if VerifySourceTree(root, policy) != nil {
		return ErrGitSource
	}
	commit, e = call("rev-parse", "HEAD^{commit}")
	if e != nil || commit != identity.commit {
		return ErrGitSource
	}
	if _, e = call("symbolic-ref", "-q", "HEAD"); !hasExitCode(e, 1) {
		return ErrGitSource
	}
	return nil
}

func gitReadArgs(args ...string) []string {
	return append([]string{"-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false"}, args...)
}
func gitReadEnv() []string {
	return []string{"GIT_TERMINAL_PROMPT=0", "GIT_OPTIONAL_LOCKS=0", "GIT_NO_REPLACE_OBJECTS=1"}
}
func hasExitCode(err error, want int) bool {
	var typed *commandExitError
	if errors.As(err, &typed) {
		return typed.code == want
	}
	var exit *exec.ExitError
	return errors.As(err, &exit) && exit.ExitCode() == want
}
func gitVersionFromOutput(raw []byte) string {
	fields := strings.Fields(string(raw))
	if len(fields) < 3 || fields[0] != "git" || fields[1] != "version" || !gitVersionText.MatchString(fields[2]) {
		return ""
	}
	return fields[2]
}
func cleanGitRoot(path string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", ErrGitSource
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", ErrGitSource
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", ErrGitSource
	}
	return filepath.Clean(resolved), nil
}

func onlyExpectedRemoteURL(raw, expected string) bool {
	lines := strings.Fields(raw)
	return len(lines) == 1 && (lines[0] == expected || lines[0] == expected+".git")
}

func gitIndexMatches(raw, tree []byte, files []FileEntryV1, ctx context.Context, root string, git boundExecutable) bool {
	plan, ok := planGitIndexMatch(raw, tree, files)
	if !ok {
		return false
	}
	digests, err := readGitBlobBatch(ctx, root, git, plan.objectIDs)
	if err != nil || len(digests) != len(plan.objectIDs) {
		return false
	}
	for path, object := range plan.index {
		if digests[object.id] != plan.expected[path].SHA256 {
			return false
		}
	}
	return true
}

type gitIndexMatchPlan struct {
	expected  map[string]FileEntryV1
	index     map[string]gitObject
	objectIDs []string
}

func planGitIndexMatch(raw, tree []byte, files []FileEntryV1) (gitIndexMatchPlan, bool) {
	expected := map[string]FileEntryV1{}
	for _, f := range files {
		expected[f.Path] = f
	}
	index := map[string]gitObject{}
	objectIDLength := 0
	for _, record := range bytes.Split(raw, []byte{0}) {
		if len(record) == 0 {
			continue
		}
		parts := bytes.SplitN(record, []byte{'\t'}, 2)
		if len(parts) != 2 {
			return gitIndexMatchPlan{}, false
		}
		meta := strings.Fields(string(parts[0]))
		if len(meta) != 3 || meta[2] != "0" || !gitObjectID.MatchString(meta[1]) {
			return gitIndexMatchPlan{}, false
		}
		if objectIDLength == 0 {
			objectIDLength = len(meta[1])
		} else if len(meta[1]) != objectIDLength {
			return gitIndexMatchPlan{}, false
		}
		path := string(parts[1])
		entry, ok := expected[path]
		if !ok || index[path].id != "" || !gitModeMatches(meta[0], entry.Mode) {
			return gitIndexMatchPlan{}, false
		}
		index[path] = gitObject{mode: meta[0], id: meta[1]}
	}
	if len(index) != len(expected) {
		return gitIndexMatchPlan{}, false
	}
	treeSeen := map[string]bool{}
	objectSeen := map[string]bool{}
	objectIDs := make([]string, 0, len(index))
	for _, record := range bytes.Split(tree, []byte{0}) {
		if len(record) == 0 {
			continue
		}
		parts := bytes.SplitN(record, []byte{'\t'}, 2)
		if len(parts) != 2 {
			return gitIndexMatchPlan{}, false
		}
		meta := strings.Fields(string(parts[0]))
		if len(meta) != 3 || meta[1] != "blob" || !gitObjectID.MatchString(meta[2]) {
			return gitIndexMatchPlan{}, false
		}
		object, ok := index[string(parts[1])]
		if !ok || object.mode != meta[0] || object.id != meta[2] {
			return gitIndexMatchPlan{}, false
		}
		if treeSeen[string(parts[1])] {
			return gitIndexMatchPlan{}, false
		}
		treeSeen[string(parts[1])] = true
		if !objectSeen[object.id] {
			objectSeen[object.id] = true
			objectIDs = append(objectIDs, object.id)
		}
	}
	if len(treeSeen) != len(expected) || len(objectIDs) == 0 {
		return gitIndexMatchPlan{}, false
	}
	return gitIndexMatchPlan{expected: expected, index: index, objectIDs: objectIDs}, true
}

func readGitBlobBatch(ctx context.Context, root string, git boundExecutable, objectIDs []string) (map[string]string, error) {
	if ctx == nil || ctx.Err() != nil || git.path == "" || git.hash == nil || !digestText.MatchString(git.digest) || len(objectIDs) == 0 || len(objectIDs) > 4096 {
		return nil, ErrGitSource
	}
	var request strings.Builder
	for _, objectID := range objectIDs {
		if !gitObjectID.MatchString(objectID) {
			return nil, ErrGitSource
		}
		request.WriteString(objectID)
		request.WriteByte('\n')
	}
	if request.Len() > int(maxGoListBytes) {
		return nil, ErrGitSource
	}
	before, err := git.hash(git.path)
	if err != nil || before != git.digest {
		return nil, ErrGitSource
	}
	command := exec.CommandContext(ctx, git.path, gitReadArgs("cat-file", "--batch=%(objectname) %(objecttype) %(objectsize)")...)
	command.Dir = root
	command.Env = []string{
		"PATH=" + os.Getenv("PATH"), "LANG=" + os.Getenv("LANG"),
		"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_TERMINAL_PROMPT=0",
		"GIT_OPTIONAL_LOCKS=0", "GIT_NO_REPLACE_OBJECTS=1",
	}
	command.WaitDelay = 250 * time.Millisecond
	command.Stdin = strings.NewReader(request.String())
	command.Stderr = io.Discard
	stdout, err := command.StdoutPipe()
	if err != nil {
		return nil, ErrGitSource
	}
	if err = command.Start(); err != nil {
		return nil, ErrGitSource
	}
	// A descendant may inherit the pipe after Git is killed. Closing our
	// read end on cancellation also bounds the synchronous batch parser.
	stopRead := context.AfterFunc(ctx, func() { _ = stdout.Close() })
	defer stopRead()
	digests, parseErr := parseGitBlobBatch(bufio.NewReaderSize(stdout, 64<<10), objectIDs)
	if parseErr != nil && command.Process != nil {
		_ = command.Process.Kill()
	}
	waitErr := command.Wait()
	after, hashErr := git.hash(git.path)
	if ctx.Err() != nil || parseErr != nil || waitErr != nil || hashErr != nil || after != git.digest {
		return nil, ErrGitSource
	}
	return digests, nil
}

func parseGitBlobBatch(reader *bufio.Reader, objectIDs []string) (map[string]string, error) {
	digests := make(map[string]string, len(objectIDs))
	var total int64
	for _, expectedID := range objectIDs {
		header, err := readGitBatchHeader(reader)
		if err != nil {
			return nil, ErrGitSource
		}
		fields := strings.Fields(header)
		if len(fields) != 3 || fields[0] != expectedID || fields[1] != "blob" {
			return nil, ErrGitSource
		}
		size, err := strconv.ParseInt(fields[2], 10, 64)
		if err != nil || size < 0 || size > sourceFileBytes || total > sourceTreeBytes-size {
			return nil, ErrGitSource
		}
		hash := sha256.New()
		written, err := io.CopyN(hash, reader, size)
		if err != nil || written != size {
			return nil, ErrGitSource
		}
		terminator, err := reader.ReadByte()
		if err != nil || terminator != '\n' {
			return nil, ErrGitSource
		}
		if _, duplicate := digests[expectedID]; duplicate {
			return nil, ErrGitSource
		}
		digests[expectedID] = hex.EncodeToString(hash.Sum(nil))
		total += size
	}
	if _, err := reader.ReadByte(); !errors.Is(err, io.EOF) {
		return nil, ErrGitSource
	}
	return digests, nil
}

func readGitBatchHeader(reader *bufio.Reader) (string, error) {
	line, err := reader.ReadSlice('\n')
	if err != nil || len(line) < 2 || len(line) > 256 {
		return "", ErrGitSource
	}
	return string(line[:len(line)-1]), nil
}

var gitObjectID = regexp.MustCompile(`^(?:[0-9a-f]{40}|[0-9a-f]{64})$`)

type gitObject struct{ mode, id string }

func gitModeMatches(mode string, want uint32) bool {
	return (want == 0o644 && mode == "100644") || (want == 0o755 && mode == "100755")
}
