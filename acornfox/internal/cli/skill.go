package cli

import (
	"context"
	_ "embed"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/acornfox/acornfox/internal/client"
)

// skillContent is the AcornFox Skill (SKILL.md with name/description
// frontmatter). skills/acornfox/SKILL.md at the repository root is a copy of
// this file for readers browsing the repo.
//
//go:embed skilldata/SKILL.md
var skillContent string

// skillName is the directory the Skill is installed under.
const skillName = "acornfox"

// cmdSkill handles the `acornfox skill` subcommands.
func (a *app) cmdSkill(ctx context.Context, args []string) int {
	if len(args) == 0 {
		return a.out.usageError("skill 需要子命令：install / print")
	}
	switch args[0] {
	case "install":
		return a.cmdSkillInstall(args[1:])
	case "print":
		fmt.Fprint(a.out.stdout, skillContent)
		return exitOK
	default:
		return a.out.usageError("未知的 skill 子命令：%s", args[0])
	}
}

// workbench is an AI workbench whose skills directory we install into.
type workbench struct {
	Name      string
	SkillsDir string // parent of <skillName>/SKILL.md
}

// cmdSkillInstall implements `skill install [--dir DIR]`. Without --dir it
// installs into every detected workbench that loads SKILL.md directories;
// with --dir it writes DIR/acornfox/SKILL.md for any other tool.
func (a *app) cmdSkillInstall(args []string) int {
	fs := flag.NewFlagSet("skill install", flag.ContinueOnError)
	fs.SetOutput(a.out.stderr)
	dir := fs.String("dir", "", "安装到指定的 skills 目录（写入 DIR/acornfox/SKILL.md）")
	rest, err := parseFlags(fs, args)
	if err != nil {
		return exitUsage
	}
	if len(rest) != 0 {
		return a.out.usageError("用法：skill install [--dir DIR]")
	}

	var targets []workbench
	if *dir != "" {
		targets = []workbench{{Name: "自定义目录", SkillsDir: *dir}}
	} else {
		home, herr := os.UserHomeDir()
		if herr != nil {
			return a.out.usageError("无法确定用户主目录：%v", herr)
		}
		targets = detectWorkbenches(home)
	}
	if len(targets) == 0 {
		return a.out.usageError("未检测到支持的 AI 工作台（Claude Code：~/.claude，Codex：~/.codex）；其他工具用 skill install --dir 指定 skills 目录，或用 skill print 输出内容")
	}

	var installed []map[string]any
	failed := 0
	for _, wb := range targets {
		path, ierr := installSkill(wb.SkillsDir)
		if ierr != nil {
			failed++
			if !a.out.json {
				a.out.humanErr("✗ %s：%v", wb.Name, ierr)
			}
			continue
		}
		installed = append(installed, map[string]any{"workbench": wb.Name, "path": path})
		if !a.out.json {
			a.out.human("✓ %s：已安装到 %s", wb.Name, path)
		}
	}

	if a.out.json {
		if len(installed) == 0 {
			a.out.emitDiagnosisJSON(client.Diagnosis{Stage: "skill", Code: "install_failed", Message: "Skill 安装失败"})
			return exitOpFailed
		}
		a.out.emitJSON(map[string]any{"installed": installed, "failed": failed})
		return exitOK
	}
	if len(installed) == 0 {
		return exitOpFailed
	}
	a.out.human("在 AI 工作台中说“用 acornfox 部署这个项目”即可。")
	return exitOK
}

// detectWorkbenches returns the workbenches present under home. A workbench
// counts as present when its config directory exists; its skills directory is
// created on install.
func detectWorkbenches(home string) []workbench {
	candidates := []struct {
		name, configDir string
	}{
		{"Claude Code", ".claude"},
		{"Codex", ".codex"},
	}
	var out []workbench
	for _, c := range candidates {
		cfg := filepath.Join(home, c.configDir)
		if fi, err := os.Stat(cfg); err == nil && fi.IsDir() {
			out = append(out, workbench{Name: c.name, SkillsDir: filepath.Join(cfg, "skills")})
		}
	}
	return out
}

// installSkill writes skillsDir/acornfox/SKILL.md and returns its path.
func installSkill(skillsDir string) (string, error) {
	dir := filepath.Join(skillsDir, skillName)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("创建目录失败：%w", err)
	}
	path := filepath.Join(dir, "SKILL.md")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(skillContent), 0o644); err != nil {
		return "", fmt.Errorf("写入文件失败：%w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return "", fmt.Errorf("写入文件失败：%w", err)
	}
	return path, nil
}
