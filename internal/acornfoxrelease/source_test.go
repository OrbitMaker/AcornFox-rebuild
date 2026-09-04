package acornfoxrelease

import (
	"os"
	"path/filepath"
	"testing"
)

func sourcePolicyFixture() SourcePolicyV1 {
	return SourcePolicyV1{SchemaVersion: 1, Product: Product, ModulePath: "github.com/acme/acornfox-fixture", GoPackages: []string{"github.com/acme/acornfox-fixture/cmd/server"}, Files: []FileEntryV1{{Path: "cmd/main.go", SHA256: sha256Text([]byte("main")), Mode: 0o644}, {Path: "scripts/run", SHA256: sha256Text([]byte("run")), Mode: 0o755}}}
}
func writeFixtureFile(t *testing.T, root, path, body string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(root, filepath.Dir(path)), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, path), []byte(body), mode); err != nil {
		t.Fatal(err)
	}
}
func TestVerifySourceTreeExactSynthetic(t *testing.T) {
	root := t.TempDir()
	policy := sourcePolicyFixture()
	writeFixtureFile(t, root, "cmd/main.go", "main", 0o644)
	writeFixtureFile(t, root, "scripts/run", "run", 0o755)
	if err := os.Mkdir(filepath.Join(root, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeFixtureFile(t, root, ".git/config", "ignored", 0o644)
	if err := VerifySourceTree(root, policy); err != nil {
		t.Fatal(err)
	}
}
func TestVerifySourceTreeRejectsUnsafeState(t *testing.T) {
	for _, tc := range []struct {
		name  string
		apply func(*testing.T, string)
	}{
		{"extra", func(t *testing.T, r string) { writeFixtureFile(t, r, "extra", "x", 0o644) }},
		{"missing", func(t *testing.T, r string) {
			if err := os.Remove(filepath.Join(r, "cmd/main.go")); err != nil {
				t.Fatal(err)
			}
		}},
		{"symlink", func(t *testing.T, r string) {
			if err := os.Remove(filepath.Join(r, "cmd/main.go")); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("../scripts/run", filepath.Join(r, "cmd/main.go")); err != nil {
				t.Fatal(err)
			}
		}},
		{"mode", func(t *testing.T, r string) {
			if err := os.Chmod(filepath.Join(r, "cmd/main.go"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"digest", func(t *testing.T, r string) { writeFixtureFile(t, r, "cmd/main.go", "other", 0o644) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			p := sourcePolicyFixture()
			writeFixtureFile(t, root, "cmd/main.go", "main", 0o644)
			writeFixtureFile(t, root, "scripts/run", "run", 0o755)
			tc.apply(t, root)
			if err := VerifySourceTree(root, p); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}
func TestSourcePolicyRejectsTraversalOrderAndDuplicate(t *testing.T) {
	for _, mutate := range []func(*SourcePolicyV1){func(p *SourcePolicyV1) { p.Files[0].Path = "../escape" }, func(p *SourcePolicyV1) { p.Files[1], p.Files[0] = p.Files[0], p.Files[1] }, func(p *SourcePolicyV1) { p.Files = append(p.Files, p.Files[0]) }} {
		p := sourcePolicyFixture()
		mutate(&p)
		if _, err := CanonicalSourcePolicyV1(p); err == nil {
			t.Fatal("accepted")
		}
	}
}

func TestSourcePolicyAllowsDotfileButRejectsGitAndControls(t *testing.T) {
	p := sourcePolicyFixture()
	p.Files[0].Path = ".gitignore"
	if _, err := CanonicalSourcePolicyV1(p); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{".git/config", "a/../b", "a//b", "a/\nb", "a/\tb", "a/\x01b", "a/\x1fb", "a/\x7fb", "/absolute"} {
		q := sourcePolicyFixture()
		q.Files[0].Path = path
		if _, err := CanonicalSourcePolicyV1(q); err == nil {
			t.Fatalf("accepted %q", path)
		}
	}
}

func TestVerifySourceTreeRejectsHardlinkAndAcceptsWorktreeGitFile(t *testing.T) {
	root := t.TempDir()
	p := sourcePolicyFixture()
	writeFixtureFile(t, root, "cmd/main.go", "main", 0o644)
	writeFixtureFile(t, root, "scripts/run", "run", 0o755)
	writeFixtureFile(t, root, ".git", "gitdir: /synthetic", 0o644)
	if err := VerifySourceTree(root, p); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(filepath.Join(root, "cmd/main.go"), filepath.Join(root, "copy")); err != nil {
		t.Fatal(err)
	}
	if err := VerifySourceTree(root, p); err == nil {
		t.Fatal("hardlink accepted")
	}
}
