package acornfoxrelease

import (
	"context"
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
