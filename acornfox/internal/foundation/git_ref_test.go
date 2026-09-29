package foundation

import "testing"

func TestGitRefHyphenatedBranchesAndOptions(t *testing.T) {
	for _, ref := range []string{"codex/mvp-smoke-demo", "feature/my-app", "release-v1.2.3", "refs/heads/my-branch"} {
		if got, err := NormalizeGitRef(ref); err != nil || got != ref {
			t.Fatalf("valid branch rejected: %q: %v", ref, err)
		}
	}
	for _, ref := range []string{"-branch", "--upload-pack=command", "branch name", "a..b", "a~1", "a^1", "a:b", "a?b", "a*b", "a[b", "a\\b"} {
		if _, err := NormalizeGitRef(ref); err == nil {
			t.Fatalf("unsafe ref accepted: %q", ref)
		}
	}
	for c := byte(0); c < 32; c++ {
		if _, err := NormalizeGitRef("branch" + string(c) + "name"); err == nil {
			t.Fatalf("control byte accepted: %d", c)
		}
	}
	if _, err := NormalizeGitRef("branch\x7fname"); err == nil {
		t.Fatal("DEL accepted")
	}
}
