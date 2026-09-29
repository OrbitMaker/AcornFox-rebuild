package pack

import (
	"archive/tar"
	"compress/gzip"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"testing"
	"time"
)

// writeTree creates files under root. Keys are slash paths; a value ending in
// "/" (empty) creates a directory.
func writeTree(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for name, content := range files {
		full := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// readTar returns the sorted list of entry names (dirs keep trailing slash) in
// the packed archive at path.
func readTar(t *testing.T, path string) []string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	var names []string
	for {
		hdr, err := tr.Next()
		if err != nil {
			break
		}
		names = append(names, hdr.Name)
	}
	sort.Strings(names)
	return names
}

func packDir(t *testing.T, root string) Result {
	t.Helper()
	res, err := Dir(root)
	if err != nil {
		t.Fatalf("Dir(%q) error: %v", root, err)
	}
	t.Cleanup(func() { _ = os.Remove(res.Path) })
	return res
}

func TestDockerfileMissing(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{"main.go": "package main"})
	if _, err := Dir(root); err != ErrDockerfileMissing {
		t.Fatalf("want ErrDockerfileMissing, got %v", err)
	}
}

func TestIgnorePatternsExceptionsAndDoubleStar(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"Dockerfile":          "FROM scratch",
		"main.go":             "package main",
		"secret.env":          "X=1",
		"keep.env":            "Y=2",
		"logs/app.log":        "log",
		"logs/keep/important": "keep",
		"a/b/c/deep.tmp":      "deep",
		"node_modules/x/y.js": "js",
		"src/vendor/lib.go":   "vendor",
		"src/main/handler.go": "handler",
	})
	writeTree(t, root, map[string]string{
		".dockerignore": "" +
			"# comment line\n" +
			"*.env\n" +
			"!keep.env\n" +
			"logs\n" +
			"!logs/keep\n" +
			"**/*.tmp\n" +
			"node_modules/\n" +
			"src/**/vendor\n",
	})

	res := packDir(t, root)
	names := readTar(t, res.Path)
	got := map[string]bool{}
	for _, n := range names {
		got[n] = true
	}

	mustHave := []string{"Dockerfile", "main.go", "keep.env", "src/main/handler.go", "logs/keep/important"}
	mustNot := []string{"secret.env", "logs/app.log", "a/b/c/deep.tmp", "node_modules/x/y.js", "src/vendor/lib.go"}

	for _, n := range mustHave {
		if !got[n] {
			t.Errorf("expected %q to be included; archive=%v", n, names)
		}
	}
	for _, n := range mustNot {
		if got[n] {
			t.Errorf("expected %q to be excluded; archive=%v", n, names)
		}
	}
}

func TestGitAndAcornfoxAlwaysExcluded(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"Dockerfile":  "FROM scratch",
		".git/config": "[core]",
		".git/HEAD":   "ref",
		".acornfox":   `{"target":"x"}`,
		"app.go":      "package main",
	})
	// Even an empty .dockerignore (no rules) must not resurrect them.
	writeTree(t, root, map[string]string{".dockerignore": "\n"})

	res := packDir(t, root)
	for _, n := range readTar(t, res.Path) {
		if n == ".acornfox" || n == ".git/" || n == ".git/config" || n == ".git/HEAD" {
			t.Errorf("%q must always be excluded", n)
		}
	}
}

func TestSymlinkStoredNotFollowed(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation is restricted on windows CI")
	}
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"Dockerfile": "FROM scratch",
		"target.txt": "hello",
	})
	if err := os.Symlink("target.txt", filepath.Join(root, "link.txt")); err != nil {
		t.Fatal(err)
	}

	res := packDir(t, root)
	f, err := os.Open(res.Path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, _ := gzip.NewReader(f)
	tr := tar.NewReader(gz)
	found := false
	for {
		hdr, err := tr.Next()
		if err != nil {
			break
		}
		if hdr.Name == "link.txt" {
			found = true
			if hdr.Typeflag != tar.TypeSymlink {
				t.Errorf("link.txt stored as type %d, want symlink", hdr.Typeflag)
			}
			if hdr.Linkname != "target.txt" {
				t.Errorf("link target = %q, want target.txt", hdr.Linkname)
			}
		}
	}
	if !found {
		t.Error("symlink entry not found in archive")
	}
}

func TestDeterministicSHA(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"Dockerfile": "FROM scratch",
		"a.txt":      "aaa",
		"dir/b.txt":  "bbb",
	})

	r1 := packDir(t, root)
	// Touch mtimes to a very different value; output must not change.
	future := time.Now().Add(72 * time.Hour)
	_ = os.Chtimes(filepath.Join(root, "a.txt"), future, future)
	_ = os.Chtimes(filepath.Join(root, "dir/b.txt"), future, future)
	r2 := packDir(t, root)

	if r1.SHA256 != r2.SHA256 {
		t.Errorf("sha differs across runs / mtimes: %s vs %s", r1.SHA256, r2.SHA256)
	}
	if r1.Bytes != r2.Bytes {
		t.Errorf("byte size differs: %d vs %d", r1.Bytes, r2.Bytes)
	}
}

func TestTooLarge(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"Dockerfile": "FROM scratch",
		"big.bin":    "this content compresses but the override cap is tiny",
	})

	orig := maxBytesOverride
	maxBytesOverride = 1 // one byte: guaranteed to be exceeded
	defer func() { maxBytesOverride = orig }()

	if _, err := Dir(root); err != ErrTooLarge {
		t.Fatalf("want ErrTooLarge, got %v", err)
	}
	// Ensure no leftover temp file matching our prefix leaks: hard to assert
	// precisely, but Dir must not return a usable Result on error.
}

func TestConvertPathSeparators(t *testing.T) {
	cases := map[string]string{
		`foo\bar`:       "foo/bar",
		`a\b\c`:         "a/b/c",
		"already/slash": "already/slash",
		`\leading`:      "/leading",
	}
	for in, want := range cases {
		if got := convertPathSeparators(in); got != want {
			t.Errorf("convertPathSeparators(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCompilePatternWindowsStyle(t *testing.T) {
	p := compilePattern(`build\output\`)
	if p == nil {
		t.Fatal("pattern compiled to nil")
	}
	if p.cleaned != "build/output" {
		t.Errorf("cleaned = %q, want build/output", p.cleaned)
	}
	if !p.dirOnly {
		t.Error("dirOnly should be true for trailing slash")
	}
	if p.exclude {
		t.Error("exclude should be false")
	}
}

func TestDeterministicHeaderFields(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"Dockerfile": "FROM scratch",
		"run.sh":     "#!/bin/sh\necho hi",
	})
	// Make run.sh executable so we can confirm the exec bit is preserved.
	if err := os.Chmod(filepath.Join(root, "run.sh"), 0o755); err != nil {
		t.Fatal(err)
	}
	res := packDir(t, root)

	f, err := os.Open(res.Path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, _ := gzip.NewReader(f)
	if gz.Name != "" {
		t.Errorf("gzip Name = %q, want empty", gz.Name)
	}
	if !gz.ModTime.IsZero() {
		t.Errorf("gzip ModTime = %v, want zero", gz.ModTime)
	}
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err != nil {
			break
		}
		if !hdr.ModTime.Equal(fixedModTime) {
			t.Errorf("%s ModTime = %v, want %v", hdr.Name, hdr.ModTime, fixedModTime)
		}
		if hdr.Uid != 0 || hdr.Gid != 0 {
			t.Errorf("%s uid/gid = %d/%d, want 0/0", hdr.Name, hdr.Uid, hdr.Gid)
		}
		if hdr.Uname != "" || hdr.Gname != "" {
			t.Errorf("%s uname/gname not empty", hdr.Name)
		}
		if hdr.Name == "run.sh" && hdr.Mode&0o111 == 0 {
			t.Errorf("run.sh lost its exec bit: mode %o", hdr.Mode)
		}
	}
}
