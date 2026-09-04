package acornfoxrelease

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

var ErrGitSource = errors.New("acornfox git source is invalid")

type commandRunner func(context.Context, string, []string, string, []string) ([]byte, error)

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
	c.Env = append([]string{"PATH=" + path, "LANG=" + lang, "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_TERMINAL_PROMPT=0", "GIT_OPTIONAL_LOCKS=0"}, env...)
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
func VerifyGitSourceV1(ctx context.Context, root string, witness Witness, policy SourcePolicyV1) error {
	return verifyGitSource(ctx, root, witness, policy, localCommand)
}
func verifyGitSource(ctx context.Context, root string, witness Witness, policy SourcePolicyV1, run commandRunner) error {
	canonical, canonicalErr := CanonicalSourcePolicyV1(policy)
	root, rootErr := cleanGitRoot(root)
	if ctx == nil || ctx.Err() != nil || run == nil || rootErr != nil || !witness.Valid() || canonicalErr != nil || sha256Text(canonical) != witness.decision.SourcePolicySHA256 || policy.ModulePath != modulePathForRepository(witness.decision.SourceRepository) {
		return ErrGitSource
	}
	call := func(args ...string) (string, error) {
		raw, e := run(ctx, "git", gitReadArgs(args...), root, gitReadEnv())
		return strings.TrimSpace(string(raw)), e
	}
	top, e := call("rev-parse", "--show-toplevel")
	top, topErr := cleanGitRoot(top)
	if e != nil || topErr != nil || top != root {
		return ErrGitSource
	}
	commit, e := call("rev-parse", "HEAD^{commit}")
	if e != nil || commit != witness.decision.SourceCommit {
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
	if e != nil || !onlyExpectedRemoteURL(origin, witness.decision.SourceRepository) {
		return ErrGitSource
	}
	pushOrigin, e := call("remote", "get-url", "--push", "--all", "origin")
	if e != nil || !onlyExpectedRemoteURL(pushOrigin, witness.decision.SourceRepository) {
		return ErrGitSource
	}
	raw, e := run(ctx, "git", gitReadArgs("ls-files", "-z", "--stage"), root, gitReadEnv())
	if e != nil {
		return ErrGitSource
	}
	tree, e := run(ctx, "git", gitReadArgs("ls-tree", "-r", "-z", witness.decision.SourceCommit), root, gitReadEnv())
	if e != nil || !gitIndexMatches(raw, tree, policy.Files, ctx, root, run) {
		return ErrGitSource
	}
	if VerifySourceTree(root, policy) != nil {
		return ErrGitSource
	}
	commit, e = call("rev-parse", "HEAD^{commit}")
	if e != nil || commit != witness.decision.SourceCommit {
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
func gitReadEnv() []string { return []string{"GIT_TERMINAL_PROMPT=0", "GIT_OPTIONAL_LOCKS=0"} }
func hasExitCode(err error, want int) bool {
	var typed *commandExitError
	if errors.As(err, &typed) {
		return typed.code == want
	}
	var exit *exec.ExitError
	return errors.As(err, &exit) && exit.ExitCode() == want
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

func gitIndexMatches(raw, tree []byte, files []FileEntryV1, ctx context.Context, root string, run commandRunner) bool {
	expected := map[string]FileEntryV1{}
	for _, f := range files {
		expected[f.Path] = f
	}
	index := map[string]gitObject{}
	for _, record := range bytes.Split(raw, []byte{0}) {
		if len(record) == 0 {
			continue
		}
		parts := bytes.SplitN(record, []byte{'\t'}, 2)
		if len(parts) != 2 {
			return false
		}
		meta := strings.Fields(string(parts[0]))
		if len(meta) != 3 || meta[2] != "0" || !gitObjectID.MatchString(meta[1]) {
			return false
		}
		path := string(parts[1])
		entry, ok := expected[path]
		if !ok || index[path].id != "" || !gitModeMatches(meta[0], entry.Mode) {
			return false
		}
		index[path] = gitObject{mode: meta[0], id: meta[1]}
	}
	if len(index) != len(expected) {
		return false
	}
	treeSeen := map[string]bool{}
	for _, record := range bytes.Split(tree, []byte{0}) {
		if len(record) == 0 {
			continue
		}
		parts := bytes.SplitN(record, []byte{'\t'}, 2)
		if len(parts) != 2 {
			return false
		}
		meta := strings.Fields(string(parts[0]))
		if len(meta) != 3 || meta[1] != "blob" || !gitObjectID.MatchString(meta[2]) {
			return false
		}
		object, ok := index[string(parts[1])]
		if !ok || object.mode != meta[0] || object.id != meta[2] {
			return false
		}
		entry := expected[string(parts[1])]
		if treeSeen[string(parts[1])] {
			return false
		}
		treeSeen[string(parts[1])] = true
		body, err := run(ctx, "git", gitReadArgs("cat-file", "blob", object.id), root, gitReadEnv())
		if err != nil || sha256Text(body) != entry.SHA256 {
			return false
		}
	}
	return len(treeSeen) == len(expected)
}

var gitObjectID = regexp.MustCompile(`^[0-9a-f]{40,64}$`)

type gitObject struct{ mode, id string }

func gitModeMatches(mode string, want uint32) bool {
	return (want == 0o644 && mode == "100644") || (want == 0o755 && mode == "100755")
}
