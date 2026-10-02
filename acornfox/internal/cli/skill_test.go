package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSkillContentHasFrontmatter(t *testing.T) {
	if !strings.HasPrefix(skillContent, "---\nname: acornfox\ndescription: ") {
		t.Fatalf("SKILL.md must start with name/description frontmatter")
	}
	for _, cmd := range []string{"acornfox deploy --json", "acornfox diagnose --json", "acornfox add postgres"} {
		if !strings.Contains(skillContent, cmd) {
			t.Fatalf("SKILL.md missing %q", cmd)
		}
	}
}

func TestSkillInstallDir(t *testing.T) {
	h := newHarness(t)
	dir := t.TempDir()
	code, out, errOut := h.run("--json", "skill", "install", "--dir", dir)
	if code != exitOK {
		t.Fatalf("exit = %d stderr=%s", code, errOut)
	}
	if m := decodeJSON(t, out); m["ok"] != true {
		t.Fatalf("ok != true: %v", m)
	}
	data, err := os.ReadFile(filepath.Join(dir, "acornfox", "SKILL.md"))
	if err != nil || string(data) != skillContent {
		t.Fatalf("SKILL.md not written: %v", err)
	}
}

func TestDetectWorkbenches(t *testing.T) {
	home := t.TempDir()
	if got := detectWorkbenches(home); len(got) != 0 {
		t.Fatalf("empty home: %v", got)
	}
	if err := os.Mkdir(filepath.Join(home, ".claude"), 0o755); err != nil {
		t.Fatal(err)
	}
	got := detectWorkbenches(home)
	if len(got) != 1 || got[0].SkillsDir != filepath.Join(home, ".claude", "skills") {
		t.Fatalf("got %v", got)
	}
}

// The repository copy must stay identical to the embedded Skill.
func TestSkillRepoCopyInSync(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "skills", "acornfox", "SKILL.md"))
	if err != nil {
		t.Skipf("repo copy not available: %v", err)
	}
	if string(data) != skillContent {
		t.Fatalf("skills/acornfox/SKILL.md differs from internal/cli/skilldata/SKILL.md")
	}
}
