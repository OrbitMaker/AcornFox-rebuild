package acornfoxrelease

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

var ErrGitSource = errors.New("acornfox git source is invalid")

type commandRunner func(context.Context, string, []string, string, []string) ([]byte, error)

func localCommand(ctx context.Context, name string, args []string, dir string, env []string) ([]byte, error) {
	c := exec.CommandContext(ctx, name, args...)
	c.Dir = dir
	path := os.Getenv("PATH")
	lang := os.Getenv("LANG")
	c.Env = append([]string{"PATH=" + path, "LANG=" + lang, "GIT_CONFIG_NOSYSTEM=1", "GIT_TERMINAL_PROMPT=0"}, env...)
	return c.Output()
}

// VerifyGitSourceV1 runs local read-only Git inspection only. A configured
// local origin is bound to the decision but is never evidence of publication.
func VerifyGitSourceV1(ctx context.Context, root string, witness Witness, policy SourcePolicyV1) error {
	return verifyGitSource(ctx, root, witness, policy, localCommand)
}
func verifyGitSource(ctx context.Context, root string, witness Witness, policy SourcePolicyV1, run commandRunner) error {
	canonical, canonicalErr := CanonicalSourcePolicyV1(policy)
	if ctx == nil || ctx.Err() != nil || !witness.Valid() || canonicalErr != nil || sha256Text(canonical) != witness.decision.SourcePolicySHA256 || policy.ModulePath != modulePathForRepository(witness.decision.SourceRepository) {
		return ErrGitSource
	}
	call := func(args ...string) (string, error) {
		raw, e := run(ctx, "git", args, root, []string{"GIT_TERMINAL_PROMPT=0"})
		return strings.TrimSpace(string(raw)), e
	}
	top, e := call("rev-parse", "--show-toplevel")
	if e != nil || filepath.Clean(top) != filepath.Clean(root) {
		return ErrGitSource
	}
	commit, e := call("rev-parse", "HEAD^{commit}")
	if e != nil || commit != witness.decision.SourceCommit {
		return ErrGitSource
	}
	if _, e = call("symbolic-ref", "-q", "HEAD"); e == nil {
		return ErrGitSource
	}
	status, e := call("status", "--porcelain=v1", "-z", "--untracked-files=all", "--ignore-submodules=none")
	if e != nil || status != "" {
		return ErrGitSource
	}
	remotes, e := call("remote")
	if e != nil || remotes != "origin" {
		return ErrGitSource
	}
	origin, e := call("remote", "get-url", "origin")
	if e != nil || (origin != witness.decision.SourceRepository && origin != witness.decision.SourceRepository+".git") {
		return ErrGitSource
	}
	raw, e := run(ctx, "git", []string{"ls-files", "-z", "--stage"}, root, []string{"GIT_TERMINAL_PROMPT=0"})
	if e != nil {
		return ErrGitSource
	}
	if !gitIndexMatches(raw, policy.Files) {
		return ErrGitSource
	}
	return VerifySourceTree(root, policy)
}
func gitIndexMatches(raw []byte, files []FileEntryV1) bool {
	expected := map[string]FileEntryV1{}
	for _, f := range files {
		expected[f.Path] = f
	}
	seen := map[string]bool{}
	for _, record := range bytes.Split(raw, []byte{0}) {
		if len(record) == 0 {
			continue
		}
		parts := bytes.SplitN(record, []byte{'\t'}, 2)
		if len(parts) != 2 {
			return false
		}
		meta := strings.Fields(string(parts[0]))
		if len(meta) != 3 || meta[1] != "0" || !regexp.MustCompile(`^[0-9a-f]{40,64}$`).MatchString(meta[2]) {
			return false
		}
		mode := meta[0]
		path := string(parts[1])
		entry, ok := expected[path]
		if !ok || seen[path] || ((entry.Mode == 0o644 && mode != "100644") || (entry.Mode == 0o755 && mode != "100755")) {
			return false
		}
		seen[path] = true
	}
	return len(seen) == len(expected)
}
