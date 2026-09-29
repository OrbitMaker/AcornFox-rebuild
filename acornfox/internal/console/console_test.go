package console

import (
	"io/fs"
	"regexp"
	"strings"
	"testing"
)

// readFile reads a file from the embedded FS or fails the test.
func readFile(t *testing.T, name string) string {
	t.Helper()
	b, err := fs.ReadFile(FS, name)
	if err != nil {
		t.Fatalf("read %s from FS: %v", name, err)
	}
	return string(b)
}

// TestRequiredFilesExist ensures the three core assets are embedded and served
// from the sub-FS root (index.html at "/").
func TestRequiredFilesExist(t *testing.T) {
	for _, name := range []string{"index.html", "app.js", "app.css"} {
		if _, err := fs.Stat(FS, name); err != nil {
			t.Errorf("expected %s in FS: %v", name, err)
		}
	}
}

// TestIndexReferencesOnlyLocalFiles checks that index.html loads only same-origin
// relative resources: no http(s):// or //cdn hrefs/srcs, and the referenced
// stylesheet and script are the local files.
func TestIndexReferencesOnlyLocalFiles(t *testing.T) {
	html := readFile(t, "index.html")

	// No external resources (CSP forbids them anyway, but assert it in source).
	extRef := regexp.MustCompile(`(?i)(href|src)\s*=\s*["'](https?:)?//`)
	if m := extRef.FindString(html); m != "" {
		t.Errorf("index.html references an external resource: %q", m)
	}

	if !strings.Contains(html, `href="app.css"`) {
		t.Error("index.html must link the local app.css")
	}
	if !strings.Contains(html, `src="app.js"`) {
		t.Error("index.html must load the local app.js")
	}
}

// TestNoInlineScriptOrStyle asserts the CSP-hostile patterns are absent from
// the embedded HTML: an inline <script> body, and any inline style="" attribute.
func TestNoInlineScriptOrStyle(t *testing.T) {
	html := readFile(t, "index.html")

	// <script> tags may only be resource references (have a src=), never a body.
	scriptTag := regexp.MustCompile(`(?is)<script([^>]*)>(.*?)</script>`)
	for _, m := range scriptTag.FindAllStringSubmatch(html, -1) {
		attrs, body := m[1], strings.TrimSpace(m[2])
		if body != "" {
			t.Errorf("index.html has an inline <script> body: %q", body)
		}
		if !strings.Contains(strings.ToLower(attrs), "src=") {
			t.Errorf("index.html has a <script> without src: %q", m[0])
		}
	}

	// <style> blocks are not allowed (styles live in app.css).
	if regexp.MustCompile(`(?is)<style[\s>]`).MatchString(html) {
		t.Error("index.html must not contain a <style> block")
	}

	// No inline style="" attribute anywhere.
	if regexp.MustCompile(`(?i)\sstyle\s*=\s*["']`).MatchString(html) {
		t.Error("index.html must not use inline style attributes")
	}
}

// TestNoInnerHTMLWithData asserts app.js never assigns to innerHTML (data must
// flow through textContent/attributes only) and contains no inline style
// attribute strings or eval.
func TestNoInnerHTMLWithData(t *testing.T) {
	js := readFile(t, "app.js")

	if regexp.MustCompile(`\.innerHTML\s*=`).MatchString(js) {
		t.Error("app.js must not assign to innerHTML; use textContent/DOM APIs")
	}
	if regexp.MustCompile(`\bouterHTML\s*=`).MatchString(js) {
		t.Error("app.js must not assign to outerHTML")
	}
	if regexp.MustCompile(`\beval\s*\(`).MatchString(js) {
		t.Error("app.js must not use eval")
	}
	// No literal inline style="" attribute strings baked into markup text.
	if regexp.MustCompile(`(?i)\bstyle\s*=\s*\\?["']`).MatchString(js) {
		t.Error("app.js must not embed inline style attribute strings")
	}
}
