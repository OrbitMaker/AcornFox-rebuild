package acornfoxrelease

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
			root, _, witness, policy, toolchain := syntheticGoReleaseRepository(t)
			mutate(t, root, &witness, policy)
			if err := VerifyGitSourceV1(context.Background(), root, witness, policy, toolchain); err == nil {
				t.Fatal("accepted " + name)
			}
		})
	}
}

func TestVerifyGitSourceV1UsesHermeticReadArgumentsAndExactDetachedExit(t *testing.T) {
	root, _, witness, policy, toolchain := syntheticGoReleaseRepository(t)
	var calls [][]string
	runner := func(ctx context.Context, name string, args []string, dir string, env []string) ([]byte, error) {
		calls = append(calls, append([]string(nil), args...))
		if len(args) >= 5 && args[4] == "symbolic-ref" {
			return nil, &commandExitError{code: 2, err: errors.New("simulated failure")}
		}
		return localCommand(ctx, name, args, dir, env)
	}
	if err := verifyGitSource(context.Background(), root, witness, policy, toolchain, runner); err == nil {
		t.Fatal("accepted symbolic-ref failure other than detached exit 1")
	}
	if len(calls) < 3 {
		t.Fatalf("calls=%q", calls)
	}
	for _, args := range calls {
		if len(args) == 1 && args[0] == "--version" {
			continue
		}
		if len(args) < 4 || args[0] != "-c" || args[1] != "core.fsmonitor=false" || args[2] != "-c" || args[3] != "core.untrackedCache=false" {
			t.Fatalf("unsealed git args: %q", args)
		}
	}
}

func TestVerifyGitSourceV1PinsDecisionCommitAndDisablesLocalFsmonitor(t *testing.T) {
	root, _, witness, policy, toolchain := syntheticGoReleaseRepository(t)
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
	if err := verifyGitSource(context.Background(), root, witness, policy, toolchain, runner); err == nil {
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

func TestVerifyGitSourceV1RejectsGitBinaryDriftAndReplacementRefs(t *testing.T) {
	root, _, witness, policy, toolchain := syntheticGoReleaseRepository(t)
	gitPath, err := resolveTrustedExecutable("git", exec.LookPath)
	if err != nil {
		t.Fatal(err)
	}
	hashCalls, commandCalls := 0, 0
	err = verifyGitSourceWithDependencies(context.Background(), root, witness, policy, toolchain, func(ctx context.Context, name string, args []string, dir string, env []string) ([]byte, error) {
		commandCalls++
		return localCommand(ctx, name, args, dir, env)
	}, func(string) (string, error) { return gitPath, nil }, func(path string) (string, error) {
		hashCalls++
		if hashCalls == 3 {
			return strings.Repeat("f", 64), nil
		}
		return hashTrustedExecutable(path)
	})
	if err == nil || commandCalls != 1 {
		t.Fatalf("git hash drift accepted: calls=%d err=%v", commandCalls, err)
	}

	gitRun(t, root, "checkout", "-qb", "replacement")
	writeReleaseFile(t, filepath.Join(root, policy.Files[0].Path), "replacement\n")
	gitRun(t, root, "add", policy.Files[0].Path)
	gitRun(t, root, "commit", "-qm", "replacement")
	replacement := gitRun(t, root, "rev-parse", "HEAD")
	gitRun(t, root, "checkout", "-q", "--detach", witness.decision.SourceCommit)
	gitRun(t, root, "replace", witness.decision.SourceCommit, replacement)
	if err := VerifyGitSourceV1(context.Background(), root, witness, policy, toolchain); err != nil {
		t.Fatalf("git replace altered sealed inspection: %v", err)
	}
	forged := toolchain
	forged.GitBinarySHA256 = strings.Repeat("0", 64)
	if err := VerifyGitSourceV1(context.Background(), root, witness, policy, forged); err == nil {
		t.Fatal("forged toolchain accepted")
	}
}

func TestGitIndexMatchesRejectsMalformedIndexEntries(t *testing.T) {
	root, _, _, policy, toolchain := syntheticGoReleaseRepository(t)
	git, err := bindExecutable("git", toolchain.GitBinarySHA256, localCommand, exec.LookPath, hashTrustedExecutable)
	if err != nil {
		t.Fatal(err)
	}
	entry := policy.Files[0]
	tree := []byte("100644 blob 0123456789012345678901234567890123456789\t" + entry.Path + "\x00")
	for name, index := range map[string][]byte{
		"nonzero stage":  []byte("100644 0123456789012345678901234567890123456789 1\t" + entry.Path + "\x00"),
		"symlink mode":   []byte("120000 0123456789012345678901234567890123456789 0\t" + entry.Path + "\x00"),
		"submodule mode": []byte("160000 0123456789012345678901234567890123456789 0\t" + entry.Path + "\x00"),
		"bad object":     []byte("100644 not-an-object 0\t" + entry.Path + "\x00"),
	} {
		t.Run(name, func(t *testing.T) {
			if gitIndexMatches(index, tree, []FileEntryV1{entry}, context.Background(), root, git) {
				t.Fatal("accepted malformed " + name)
			}
		})
	}
}

func TestPlanGitIndexMatchSupportsSHA1AndSHA256AndDeduplicates(t *testing.T) {
	for _, length := range []int{40, 64} {
		t.Run(fmt.Sprintf("oid-%d", length), func(t *testing.T) {
			objectID := strings.Repeat("a", length)
			files := []FileEntryV1{
				{Path: "a.txt", SHA256: strings.Repeat("b", 64), Mode: 0o644},
				{Path: "bin/tool", SHA256: strings.Repeat("b", 64), Mode: 0o755},
			}
			index := []byte("100644 " + objectID + " 0\ta.txt\x00100755 " + objectID + " 0\tbin/tool\x00")
			tree := []byte("100644 blob " + objectID + "\ta.txt\x00100755 blob " + objectID + "\tbin/tool\x00")
			plan, ok := planGitIndexMatch(index, tree, files)
			if !ok || len(plan.objectIDs) != 1 || plan.objectIDs[0] != objectID || len(plan.index) != 2 {
				t.Fatalf("plan = %#v, ok=%v", plan, ok)
			}
		})
	}
	for _, length := range []int{39, 41, 63, 65} {
		objectID := strings.Repeat("a", length)
		entry := FileEntryV1{Path: "a", SHA256: strings.Repeat("b", 64), Mode: 0o644}
		index := []byte("100644 " + objectID + " 0\ta\x00")
		tree := []byte("100644 blob " + objectID + "\ta\x00")
		if _, ok := planGitIndexMatch(index, tree, []FileEntryV1{entry}); ok {
			t.Fatalf("accepted %d-character object id", length)
		}
	}
}

func TestParseGitBlobBatchHandlesBinaryBodiesAndRejectsProtocolDrift(t *testing.T) {
	id := strings.Repeat("a", 40)
	body := []byte{'a', 0, '\n', 'b'}
	valid := func() []byte {
		var output bytes.Buffer
		fmt.Fprintf(&output, "%s blob %d\n", id, len(body))
		output.Write(body)
		output.WriteByte('\n')
		return output.Bytes()
	}
	digests, err := parseGitBlobBatch(bufio.NewReader(bytes.NewReader(valid())), []string{id})
	if err != nil || digests[id] != sha256Text(body) {
		t.Fatalf("binary batch = %#v, %v", digests, err)
	}
	for name, mutate := range map[string]func([]byte) []byte{
		"wrong id":       func(raw []byte) []byte { return bytes.Replace(raw, []byte(id), []byte(strings.Repeat("b", 40)), 1) },
		"wrong type":     func(raw []byte) []byte { return bytes.Replace(raw, []byte(" blob "), []byte(" tree "), 1) },
		"bad size":       func(raw []byte) []byte { return bytes.Replace(raw, []byte(" blob 4\n"), []byte(" blob -1\n"), 1) },
		"truncated":      func(raw []byte) []byte { return raw[:len(raw)-2] },
		"bad terminator": func(raw []byte) []byte { raw[len(raw)-1] = 0; return raw },
		"extra output":   func(raw []byte) []byte { return append(raw, 'x') },
	} {
		t.Run(name, func(t *testing.T) {
			raw := mutate(append([]byte(nil), valid()...))
			if _, err := parseGitBlobBatch(bufio.NewReader(bytes.NewReader(raw)), []string{id}); err == nil {
				t.Fatal("accepted malformed batch output")
			}
		})
	}
}

func TestVerifyGitSourceUsesOnePrivateBatchInsteadOfPerBlobRunnerCalls(t *testing.T) {
	root, _, witness, policy, toolchain := syntheticGoReleaseRepository(t)
	hashCalls, commandCalls, legacyCatFileCalls := 0, 0, 0
	err := verifyGitSourceWithDependencies(context.Background(), root, witness, policy, toolchain, func(ctx context.Context, name string, args []string, dir string, env []string) ([]byte, error) {
		commandCalls++
		for _, arg := range args {
			if arg == "cat-file" {
				legacyCatFileCalls++
			}
		}
		return localCommand(ctx, name, args, dir, env)
	}, exec.LookPath, func(path string) (string, error) {
		hashCalls++
		return hashTrustedExecutable(path)
	})
	if err != nil {
		t.Fatalf("verifyGitSourceWithDependencies() error = %v", err)
	}
	if legacyCatFileCalls != 0 || commandCalls > 16 || hashCalls > 36 {
		t.Fatalf("legacy work remained: commands=%d hash=%d cat-file=%d", commandCalls, hashCalls, legacyCatFileCalls)
	}
}

func TestReadGitBlobBatchRechecksExecutableAndHonorsCancellation(t *testing.T) {
	t.Run("hermetic exact-object command", func(t *testing.T) {
		root := t.TempDir()
		script := filepath.Join(root, "fake-git")
		body := "#!/bin/sh\n" +
			"test \"$1\" = -c && test \"$2\" = core.fsmonitor=false && test \"$3\" = -c && test \"$4\" = core.untrackedCache=false || exit 2\n" +
			"test \"$5\" = cat-file && test \"$6\" = '--batch=%(objectname) %(objecttype) %(objectsize)' || exit 3\n" +
			"test \"$GIT_CONFIG_NOSYSTEM\" = 1 && test \"$GIT_CONFIG_GLOBAL\" = /dev/null && test \"$GIT_NO_REPLACE_OBJECTS\" = 1 || exit 4\n" +
			"IFS= read -r oid || exit 5\nprintf '%s blob 1\\nx\\n' \"$oid\"\n"
		if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
		digest := strings.Repeat("a", 64)
		git := boundExecutable{path: script, digest: digest, hash: func(string) (string, error) { return digest, nil }}
		objectID := strings.Repeat("c", 40)
		digests, err := readGitBlobBatch(context.Background(), root, git, []string{objectID})
		if err != nil || digests[objectID] != sha256Text([]byte("x")) {
			t.Fatalf("hermetic batch = %#v, %v", digests, err)
		}
	})

	t.Run("executable drift", func(t *testing.T) {
		root := t.TempDir()
		script := filepath.Join(root, "fake-git")
		if err := os.WriteFile(script, []byte("#!/bin/sh\nIFS= read -r oid || exit 1\nprintf '%s blob 1\\nx\\n' \"$oid\"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		digest := strings.Repeat("a", 64)
		hashCalls := 0
		git := boundExecutable{path: script, digest: digest, hash: func(string) (string, error) {
			hashCalls++
			if hashCalls == 2 {
				return strings.Repeat("b", 64), nil
			}
			return digest, nil
		}}
		if _, err := readGitBlobBatch(context.Background(), root, git, []string{strings.Repeat("c", 40)}); err == nil || hashCalls != 2 {
			t.Fatalf("drift error/hash calls = %v/%d", err, hashCalls)
		}
	})

	t.Run("context cancellation", func(t *testing.T) {
		root := t.TempDir()
		script := filepath.Join(root, "fake-git")
		if err := os.WriteFile(script, []byte("#!/bin/sh\n/bin/sleep 30\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		digest := strings.Repeat("a", 64)
		git := boundExecutable{path: script, digest: digest, hash: func(string) (string, error) { return digest, nil }}
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		started := time.Now()
		if _, err := readGitBlobBatch(ctx, root, git, []string{strings.Repeat("c", 40)}); err == nil || time.Since(started) > 2*time.Second {
			t.Fatalf("cancellation error/duration = %v/%s", err, time.Since(started))
		}
	})
}
