package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// cmdSkill handles the `acornfox skill install` command.
func (a *app) cmdSkill(ctx context.Context, args []string) int {
	if len(args) == 0 {
		return a.out.usageError("skill 需要子命令：install")
	}

	sub := args[0]
	switch sub {
	case "install":
		return a.cmdSkillInstall(ctx, args[1:])
	default:
		return a.out.usageError("未知的 skill 子命令：%s", sub)
	}
}

// cmdSkillInstall installs the AcornFox Skill to detected AI workbenches.
func (a *app) cmdSkillInstall(ctx context.Context, args []string) int {
	// Detect AI workbenches
	workbenches := detectWorkbenches()

	if len(workbenches) == 0 {
		a.out.human("未检测到支持的 AI 工作台")
		a.out.human("")
		a.out.human("支持的工作台：")
		a.out.human("  • Claude Code")
		a.out.human("  • Cursor")
		a.out.human("  • Windsurf (WorkBuddy)")
		a.out.human("  • 豆包 MarsCode")
		a.out.human("  • 通义灵码")
		return exitUsage
	}

	// Get Skill content
	skillContent, err := getSkillContent()
	if err != nil {
		return a.out.fail(fmt.Errorf("读取 Skill 内容失败: %w", err))
	}

	// Install to each detected workbench
	installed := 0
	failed := 0

	for _, wb := range workbenches {
		if err := installSkill(wb, skillContent); err != nil {
			a.out.human("✗ %s: %v", wb.Name, err)
			failed++
		} else {
			a.out.human("✓ %s: 已安装到 %s", wb.Name, wb.SkillPath)
			installed++
		}
	}

	a.out.human("")
	if installed > 0 {
		a.out.human("成功安装到 %d 个工作台", installed)
		a.out.human("")
		a.out.human("使用方法：")
		a.out.human("  在 AI 工作台中说：\"帮我部署这个项目\"")
		a.out.human("  AI 将自动使用 AcornFox 完成部署")
		return exitOK
	}

	return 1
}

// workbench represents a detected AI workbench.
type workbench struct {
	Name      string
	SkillPath string
}

// detectWorkbenches finds installed AI workbenches.
func detectWorkbenches() []workbench {
	var result []workbench

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return result
	}

	// Claude Code
	claudeSkillDir := filepath.Join(homeDir, ".claude", "skills")
	if _, err := os.Stat(claudeSkillDir); err == nil {
		result = append(result, workbench{
			Name:      "Claude Code",
			SkillPath: filepath.Join(claudeSkillDir, "acornfox.md"),
		})
	}

	// Cursor
	cursorSkillDir := filepath.Join(homeDir, ".cursor", "skills")
	if _, err := os.Stat(cursorSkillDir); err == nil {
		result = append(result, workbench{
			Name:      "Cursor",
			SkillPath: filepath.Join(cursorSkillDir, "acornfox.md"),
		})
	}

	// Windsurf (WorkBuddy) - macOS
	if runtime.GOOS == "darwin" {
		windsurfSkillDir := filepath.Join(homeDir, "Library", "Application Support", "Windsurf", "User", "globalStorage", "windsurf.windsurf", "skills")
		if _, err := os.Stat(windsurfSkillDir); err == nil {
			result = append(result, workbench{
				Name:      "Windsurf",
				SkillPath: filepath.Join(windsurfSkillDir, "acornfox.md"),
			})
		}
	} else if runtime.GOOS == "windows" {
		appData := os.Getenv("APPDATA")
		if appData != "" {
			windsurfSkillDir := filepath.Join(appData, "Windsurf", "User", "globalStorage", "windsurf.windsurf", "skills")
			if _, err := os.Stat(windsurfSkillDir); err == nil {
				result = append(result, workbench{
					Name:      "Windsurf",
					SkillPath: filepath.Join(windsurfSkillDir, "acornfox.md"),
				})
			}
		}
	} else {
		// Linux
		windsurfSkillDir := filepath.Join(homeDir, ".config", "Windsurf", "User", "globalStorage", "windsurf.windsurf", "skills")
		if _, err := os.Stat(windsurfSkillDir); err == nil {
			result = append(result, workbench{
				Name:      "Windsurf",
				SkillPath: filepath.Join(windsurfSkillDir, "acornfox.md"),
			})
		}
	}

	// 豆包 MarsCode
	marscodeSkillDir := filepath.Join(homeDir, ".marscode", "skills")
	if _, err := os.Stat(marscodeSkillDir); err == nil {
		result = append(result, workbench{
			Name:      "豆包 MarsCode",
			SkillPath: filepath.Join(marscodeSkillDir, "acornfox.md"),
		})
	}

	// 通义灵码
	tongyiSkillDir := filepath.Join(homeDir, ".tongyi", "skills")
	if _, err := os.Stat(tongyiSkillDir); err == nil {
		result = append(result, workbench{
			Name:      "通义灵码",
			SkillPath: filepath.Join(tongyiSkillDir, "acornfox.md"),
		})
	}

	return result
}

// getSkillContent returns the AcornFox Skill content.
func getSkillContent() (string, error) {
	// Try to read from embedded Skill file (will be added later)
	// For now, return the embedded content
	return embeddedSkillContent, nil
}

// installSkill installs the Skill content to a workbench.
func installSkill(wb workbench, content string) error {
	// Create directory if not exists
	dir := filepath.Dir(wb.SkillPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("创建目录失败: %w", err)
	}

	// Write Skill file
	if err := os.WriteFile(wb.SkillPath, []byte(content), 0644); err != nil {
		return fmt.Errorf("写入文件失败: %w", err)
	}

	return nil
}

// embeddedSkillContent is the AcornFox Skill content.
// This will be replaced with an embedded file system later.
const embeddedSkillContent = `# AcornFox - AI 工作台集成

让 AI 一句话部署你的应用到自己的服务器。

## 命令速查

### 配置服务器
` + "```bash" + `
acornfox target add my-server --ssh user@server-ip
` + "```" + `

### 部署应用
` + "```bash" + `
# 部署当前目录
acornfox deploy

# 部署 Git 仓库
acornfox deploy --git https://github.com/user/repo

# 部署镜像
acornfox deploy --image nginx:latest --app my-app
` + "```" + `

**重要**: 部署是异步的，需要查询状态！

### 查询状态
` + "```bash" + `
acornfox status --json
` + "```" + `

状态: ` + "`checking`" + ` → ` + "`live`" + ` (成功) / ` + "`failed`" + ` (失败)

### 诊断失败
` + "```bash" + `
acornfox diagnose --json
` + "```" + `

### 添加数据库
` + "```bash" + `
acornfox add postgres --app my-app
acornfox add mysql --app my-app
acornfox add redis --app my-app
` + "```" + `

### 生命周期
` + "```bash" + `
acornfox stop/start/restart --app my-app
acornfox delete --app my-app
acornfox rollback --app my-app
` + "```" + `

## AI 工作流程

### 1. 首次部署（无 Dockerfile）

` + "```" + `
1. 检查项目类型（package.json, requirements.txt, go.mod）
2. 生成对应的 Dockerfile
3. 执行: acornfox deploy
4. 等待 2-3 秒
5. 查询: acornfox status --json
6. 根据状态处理:
   - checking: 告诉用户"正在部署"
   - live: 告诉用户访问地址
   - failed: 读取诊断并修复
` + "```" + `

### 2. 失败修复

常见错误码:
- ` + "`dockerfile_missing`" + `: 生成 Dockerfile
- ` + "`build_failed`" + `: 检查日志修复依赖
- ` + "`port_not_listening`" + `: 检查端口配置
- ` + "`data/unpersisted_database`" + `: 添加数据卷

### 3. Dockerfile 模板

**Node.js:**
` + "```dockerfile" + `
FROM node:18-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY . .
EXPOSE 3000
CMD ["node", "index.js"]
` + "```" + `

**Python:**
` + "```dockerfile" + `
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 8000
CMD ["python", "app.py"]
` + "```" + `

**Go:**
` + "```dockerfile" + `
FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY go.* ./
RUN go mod download
COPY . .
RUN go build -o main .

FROM alpine:latest
RUN apk --no-cache add ca-certificates
COPY --from=builder /app/main ./
EXPOSE 8080
CMD ["./main"]
` + "```" + `

## 重要提示

1. **异步模式**: deploy 后必须查询 status
2. **JSON 输出**: 优先使用 --json 解析输出
3. **应用名**: 首次部署后自动保存在 .acornfox
4. **数据持久化**: 添加 volume 到需要保存的目录
5. **中国大陆**: 域名需备案，否则用 IP:端口访问

完整文档: https://acornfox.dev/docs
`
