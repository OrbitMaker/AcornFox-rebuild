# N6 首发验收清单

根据 `docs/acornfox-strategy-roadmap.md` 第 6.2 节，在一台干净的国内云主机（Ubuntu 24.04 amd64）上，由一名未参与开发的人完成以下 7 项检查。

## 验收环境要求

- **服务器**：干净的国内云主机（Ubuntu 24.04 amd64）
- **客户端**：Windows 或 macOS 电脑
- **验收人**：未参与开发的人
- **目标工作台**：至少一个（Claude Code, Cursor, Windsurf, 豆包 MarsCode, 通义灵码）

---

## 1. 一条命令安装并初始化 ✅

### 操作步骤

```bash
# 在干净的 Ubuntu 24.04 服务器上执行
curl -fsSL https://raw.githubusercontent.com/acornfox/acornfox/main/scripts/install/install.sh | sudo bash
```

### 验收标准

- [ ] 安装脚本执行成功，无致命错误
- [ ] Docker 已安装并运行（`docker ps` 成功）
- [ ] Caddy 已安装（`caddy version` 成功）
- [ ] systemd 服务已启动
  - [ ] `systemctl status acornfox-server` 显示 active (running)
  - [ ] `systemctl status acornfox-runner` 显示 active (running)
- [ ] 数据库已初始化（`/var/lib/acornfox/acornfox.db` 存在）
- [ ] 管理员令牌已生成（`/root/.acornfox-token` 存在）

### 初始化测试

```bash
# 在本地电脑打开控制台
acornfox open
```

- [ ] 浏览器自动打开控制台页面
- [ ] 页面加载正常，无 JS 错误
- [ ] 可以看到应用列表（空列表）

---

## 2. CLI 和 Skill 安装 ✅

### 在 Windows 或 macOS 电脑上

```bash
# 安装 CLI
curl -fsSL https://acornfox.dev/install-cli.sh | bash

# 或手动安装
# macOS: 下载 acornfox_darwin_amd64 (Intel) 或 acornfox_darwin_arm64 (Apple Silicon)
# Windows: 下载 acornfox_windows_amd64.exe

# 验证安装
acornfox version

# 配置目标服务器
acornfox target add my-server --ssh user@server-ip

# 测试连接
acornfox apps
```

### 在 AI 工作台中安装 Skill

```bash
acornfox skill install
```

### 验收标准

- [ ] CLI 安装成功，`acornfox version` 输出版本号
- [ ] 目标服务器配置成功
- [ ] `acornfox apps` 返回空列表（无错误）
- [ ] Skill 安装成功，输出类似：
  ```
  ✓ Claude Code：已安装到 /Users/xxx/.claude/skills/acornfox/SKILL.md
  ```
  其他工具：`acornfox skill install --dir <该工具的 skills 目录>`，或 `acornfox skill print` 复制内容
- [ ] Skill 文件存在于正确位置，开头有 `name`/`description` frontmatter
- [ ] 在 Claude Code 中输入 `/acornfox` 或说“用 acornfox 部署”能触发 Skill

---

## 3. AI 自动生成 Dockerfile 并部署 ⏳

### 准备测试项目

创建一个没有 Dockerfile 的项目，例如 Node.js 项目：

```bash
mkdir test-app && cd test-app
npm init -y
npm install express

# 创建简单的 Express 应用
cat > index.js << 'EOF'
const express = require('express');
const app = express();
const port = process.env.PORT || 3000;

app.get('/', (req, res) => {
  res.send('Hello from AcornFox!');
});

app.listen(port, '0.0.0.0', () => {
  console.log(`Server running on port ${port}`);
});
EOF
```

### 在 AI 工作台中执行

在 AI 工作台（已安装 AcornFox Skill）中说：

```
帮我部署这个项目
```

### 验收标准

- [ ] AI 识别项目类型（Node.js）
- [ ] AI 生成合适的 Dockerfile
- [ ] AI 执行 `acornfox deploy`
- [ ] AI 等待部署完成（查询 `acornfox status`）
- [ ] AI 返回可访问的地址（IP:端口 或 域名）
- [ ] 浏览器访问该地址，显示 "Hello from AcornFox!"

### 预期 AI 行为

1. 检查项目文件（package.json）
2. 生成 Dockerfile（Node.js 18-alpine + npm install）
3. 执行 `acornfox deploy`
4. 等待 2-3 秒
5. 查询 `acornfox status --json`
6. 解析 JSON，提取访问地址
7. 告诉用户访问地址

---

## 4. 部署失败诊断与修复 ⏳

### 故意制造失败

修改 Dockerfile 引入错误：

```dockerfile
FROM node:18-alpine
WORKDIR /app
COPY package*.json ./
RUN npm install --wrong-flag
COPY . .
EXPOSE 3000
CMD ["node", "index.js"]
```

### 在 AI 工作台中重新部署

```
重新部署
```

### 验收标准

- [ ] 部署失败（状态为 `failed`）
- [ ] AI 执行 `acornfox diagnose --json` 或读取 status 中的诊断
- [ ] AI 读取结构化诊断：
  ```json
  {
    "stage": "build",
    "code": "build_failed",
    "message": "镜像构建失败",
    "log_excerpt": "...",
    "hint": "检查 Dockerfile 中的 RUN 命令"
  }
  ```
- [ ] AI 根据诊断修复 Dockerfile（移除 `--wrong-flag`）
- [ ] AI 自动重新部署
- [ ] 重新部署成功，应用可访问

---

## 5. 域名 HTTPS 与未备案提示 ⏳

### 测试场景 A：已备案域名

```bash
# 绑定已备案域名
acornfox domain add example.com --app test-app
```

### 验收标准 A

- [ ] Caddy 自动申请 HTTPS 证书
- [ ] 浏览器访问 `https://example.com`，显示应用内容
- [ ] 证书有效，无安全警告

### 测试场景 B：未备案域名

```bash
# 尝试绑定未备案域名
acornfox domain add unregistered.com --app test-app
```

### 验收标准 B

- [ ] 系统返回明确提示：
  ```
  ⚠️  域名未备案
  
  中国大陆服务器上，未备案域名无法使用 80/443 端口。
  
  你可以：
  1. 到域名服务商完成 ICP 备案
  2. 使用 IP:端口 访问（当前地址：http://1.2.3.4:18810）
  3. 将应用部署到香港或海外服务器
  ```
- [ ] IP:端口 访问不受影响
- [ ] 应用仍可通过 `http://server-ip:port` 访问

---

## 6. 生命周期与数据持久化 ⏳

### 创建带数据卷的应用

```bash
# 添加数据卷
acornfox volume add data --path /app/data --app test-app

# 在应用中写入数据
curl http://server-ip:port/write-data
```

### 生命周期操作

```bash
# 停止应用
acornfox stop --app test-app

# 启动应用
acornfox start --app test-app

# 重新部署（新版本）
# 修改 index.js 添加新功能
acornfox redeploy --app test-app
```

### 验收标准

- [ ] 停止后，应用无法访问
- [ ] 启动后，应用恢复访问
- [ ] 重新部署后：
  - [ ] 新功能生效
  - [ ] 数据卷内容保留（`/app/data` 中的文件未丢失）
- [ ] 查看状态：`acornfox status --app test-app`
  - [ ] 显示当前状态（`live` / `stopped`）
  - [ ] 显示部署历史和版本
- [ ] 查看日志：`acornfox logs --app test-app`
  - [ ] 输出应用日志
  - [ ] 包含时间戳
- [ ] 查看指标：`acornfox stats --app test-app`
  - [ ] 显示 CPU、内存使用率
  - [ ] 显示网络流量

---

## 7. 目标工作台全部通过 5 项检查 ⏳

对每个目标工作台（Claude Code, Cursor, Windsurf, 豆包 MarsCode, 通义灵码），完成以下 5 项检查：

### 7.1 Skill 安装

- [ ] `acornfox skill install` 识别工作台
- [ ] Skill 文件放到正确位置
- [ ] 文件格式正确（Markdown）

### 7.2 CLI 可执行

- [ ] 在工作台终端执行 `acornfox --help` 成功
- [ ] 在工作台终端执行 `acornfox apps` 成功
- [ ] AI 可以调用 `acornfox` 命令

### 7.3 JSON 输出可解析

- [ ] `acornfox status --json` 输出有效 JSON
- [ ] AI 可以解析 JSON 并提取信息（应用名、状态、URL）
- [ ] `acornfox diagnose --json` 输出结构化诊断

### 7.4 诊断可读

- [ ] 部署失败时，诊断包含：
  - [ ] 失败阶段（`stage`）
  - [ ] 错误码（`code`）
  - [ ] 人类可读的消息（`message`）
  - [ ] 日志摘录（`log_excerpt`）
  - [ ] 修复建议（`hint`）
- [ ] AI 可以根据诊断修复问题

### 7.5 AI 遵循 Skill 完整流程

在该工作台中，用真实项目跑通：

1. **生成 Dockerfile**
   - [ ] AI 根据项目类型生成正确的 Dockerfile
   
2. **部署**
   - [ ] AI 执行 `acornfox deploy`
   - [ ] AI 等待部署完成
   
3. **失败读诊断**
   - [ ] 故意引入错误
   - [ ] AI 读取诊断（`acornfox diagnose` 或 status）
   
4. **修复**
   - [ ] AI 根据诊断修复 Dockerfile 或配置
   
5. **重新部署**
   - [ ] AI 自动重新部署
   - [ ] 部署成功，返回访问地址

---

## 验收通过标准

- **前 6 项必须全部通过**
- **第 7 项至少 3 个工作台通过全部 5 项检查**（首批目标工作台）

通过后，AcornFox 单机版即可开源首发。

---

## 验收记录

| 检查项 | 状态 | 验收人 | 日期 | 备注 |
|--------|------|--------|------|------|
| 1. 一条命令安装 | ⏳ 待验收 | - | - | - |
| 2. CLI 和 Skill 安装 | ⏳ 待验收 | - | - | - |
| 3. AI 生成 Dockerfile 并部署 | ⏳ 待验收 | - | - | - |
| 4. 失败诊断与修复 | ⏳ 待验收 | - | - | - |
| 5. 域名 HTTPS 与未备案提示 | ⏳ 待验收 | - | - | - |
| 6. 生命周期与数据持久化 | ⏳ 待验收 | - | - | - |
| 7. 目标工作台检查 | ⏳ 待验收 | - | - | - |

---

## 已知限制

1. **首发不包含 MCP 支持**（按决策记录，MCP 非首发必做）
2. **私有 Git 仓库不支持**（首发只支持公开 HTTPS Git）
3. **推送自动部署不支持**（首发只支持手动部署）
4. **云版功能未包含**（首发只有单机版）

---

## 下一步

验收通过后：

1. 创建 GitHub Release（v0.2.0）
2. 构建跨平台二进制文件
3. 更新官网安装脚本的下载链接
4. 发布开源公告
5. 进入阶段 2：首发验证（找 10 名 Vibe Coder 测试）
