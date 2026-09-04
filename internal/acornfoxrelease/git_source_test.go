package acornfoxrelease

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifyGitSourceV1RejectsCheckoutAndRemoteDrift(t *testing.T) {
	for name, mutate := range map[string]func(*testing.T, string, *Witness, SourcePolicyV1){
		"attached branch": func(t *testing.T, root string, _ *Witness, _ SourcePolicyV1) {
			gitRun(t, root, "checkout", "-qb", "fixture-branch")
		},
		"dirty tracked file": func(t *testing.T, root string, _ *Witness, policy SourcePolicyV1) {
			writeReleaseFile(t, filepath.Join(root, policy.Files[0].Path), "changed\n")
		},
		"untracked file": func(t *testing.T, root string, _ *Witness, _ SourcePolicyV1) {
			writeReleaseFile(t, filepath.Join(root, "untracked"), "x\n")
		},
		"wrong head": func(t *testing.T, _ string, witness *Witness, _ SourcePolicyV1) {
			witness.decision.SourceCommit = strings.Repeat("b", 40)
			raw, err := CanonicalDecisionV1(witness.decision)
			if err != nil {
				t.Fatal(err)
			}
			var parsed error
			*witness, parsed = ParseDecisionV1(raw, sha256Text(raw))
			if parsed != nil {
				t.Fatal(parsed)
			}
		},
		"wrong origin": func(t *testing.T, root string, _ *Witness, _ SourcePolicyV1) {
			gitRun(t, root, "remote", "set-url", "origin", "https://github.com/acme/other")
		},
		"extra remote": func(t *testing.T, root string, _ *Witness, _ SourcePolicyV1) {
			gitRun(t, root, "remote", "add", "mirror", "https://github.com/acme/mirror")
		},
		"symlink worktree": func(t *testing.T, root string, _ *Witness, policy SourcePolicyV1) {
			path := filepath.Join(root, policy.Files[0].Path)
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("/tmp/does-not-exist", path); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			root, _, witness, policy, _ := syntheticGoReleaseRepository(t)
			mutate(t, root, &witness, policy)
			if err := VerifyGitSourceV1(context.Background(), root, witness, policy); err == nil {
				t.Fatal("accepted " + name)
			}
		})
	}
}

func TestVerifyGitSourceV1UsesHermeticReadArgumentsAndExactDetachedExit(t *testing.T) {
	root, _, witness, policy, _ := syntheticGoReleaseRepository(t)
	var calls [][]string
	runner := func(ctx context.Context, name string, args []string, dir string, env []string) ([]byte, error) {
		calls = append(calls, append([]string(nil), args...))
		if len(args) >= 5 && args[4] == "symbolic-ref" {
			return nil, &commandExitError{code: 2, err: errors.New("simulated failure")}
		}
		return localCommand(ctx, name, args, dir, env)
	}
	if err := verifyGitSource(context.Background(), root, witness, policy, runner); err == nil {
		t.Fatal("accepted symbolic-ref failure other than detached exit 1")
	}
	if len(calls) < 3 {
		t.Fatalf("calls=%q", calls)
	}
	for _, args := range calls {
		if len(args) < 4 || args[0] != "-c" || args[1] != "core.fsmonitor=false" || args[2] != "-c" || args[3] != "core.untrackedCache=false" {
			t.Fatalf("unsealed git args: %q", args)
		}
	}
}

func TestVerifyGitSourceV1PinsDecisionCommitAndDisablesLocalFsmonitor(t *testing.T) {
	root, _, witness, policy, _ := syntheticGoReleaseRepository(t)
	marker := filepath.Join(t.TempDir(), "fsmonitor-ran")
	hook := filepath.Join(t.TempDir(), "fsmonitor-hook")
	if err := os.WriteFile(hook, []byte("#!/bin/sh\ntouch '"+marker+"'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	gitRun(t, root, "config", "core.fsmonitor", hook)
	indexPath := filepath.Join(root, ".git", "index")
	before, err := os.ReadFile(indexPath)
	if err != nil {
		t.Fatal(err)
	}
	var revParseCalls int
	var lsTreeCommit string
	runner := func(ctx context.Context, name string, args []string, dir string, env []string) ([]byte, error) {
		if len(args) >= 5 && args[4] == "rev-parse" && args[5] == "HEAD^{commit}" {
			revParseCalls++
			if revParseCalls == 2 {
				return []byte(strings.Repeat("f", 40) + "\n"), nil
			}
		}
		if len(args) >= 5 && args[4] == "ls-tree" {
			lsTreeCommit = args[len(args)-1]
		}
		return localCommand(ctx, name, args, dir, env)
	}
	if err := verifyGitSource(context.Background(), root, witness, policy, runner); err == nil {
		t.Fatal("accepted post-observation head drift")
	}
	if lsTreeCommit != witness.decision.SourceCommit {
		t.Fatalf("ls-tree commit=%q want=%q", lsTreeCommit, witness.decision.SourceCommit)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("repo fsmonitor hook ran: %v", err)
	}
	after, err := os.ReadFile(indexPath)
	if err != nil || string(before) != string(after) {
		t.Fatalf("index changed: %v", err)
	}
}

func TestGitIndexMatchesRejectsMalformedIndexEntries(t *testing.T) {
	root, _, _, policy, _ := syntheticGoReleaseRepository(t)
	entry := policy.Files[0]
	tree := []byte("100644 blob 0123456789012345678901234567890123456789\t" + entry.Path + "\x00")
	for name, index := range map[string][]byte{
		"nonzero stage":  []byte("100644 0123456789012345678901234567890123456789 1\t" + entry.Path + "\x00"),
		"symlink mode":   []byte("120000 0123456789012345678901234567890123456789 0\t" + entry.Path + "\x00"),
		"submodule mode": []byte("160000 0123456789012345678901234567890123456789 0\t" + entry.Path + "\x00"),
		"bad object":     []byte("100644 not-an-object 0\t" + entry.Path + "\x00"),
	} {
		t.Run(name, func(t *testing.T) {
			if gitIndexMatches(index, tree, []FileEntryV1{entry}, context.Background(), root, localCommand) {
				t.Fatal("accepted malformed " + name)
			}
		})
	}
}
