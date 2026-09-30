# AcornFox Skill - AI 工作台集成

让 AI 一句话部署你的应用到自己的服务器。

## 概述

AcornFox 是一个开源的应用部署平台，让你通过简单的命令在自己的 Linux 服务器上部署应用。这个 Skill 帮助 AI 助手理解如何使用 AcornFox 完成部署任务。

## 核心能力

- **一键部署**: 上传本地项目、Git 仓库或 Docker 镜像
- **自动诊断**: 部署失败时返回结构化诊断信息
- **生命周期管理**: 启动、停止、重启、重新部署应用
- **附加服务**: 一键添加 PostgreSQL/MySQL/Redis 数据库
- **日志与指标**: 查看应用日志和资源使用情况
- **域名 HTTPS**: 自动申请 SSL 证书（需已备案域名）

## 命令参考

### 1. 配置服务器连接

首次使用需要配置服务器：

\`\`\`bash
acornfox target add my-server --ssh user@your-server-ip
\`\`\`

- `my-server`: 给服务器起个名字
- `--ssh user@your-server-ip`: SSH 连接信息
- 使用用户现有的 SSH 密钥，无需额外配置

### 2. 部署应用

\`\`\`bash
# 部署当前目录（自动打包上传）
cd /path/to/project
acornfox deploy

# 部署 Git 仓库
acornfox deploy --git https://github.com/user/repo

# 部署 Docker 镜像
acornfox deploy --image nginx:latest --app my-app
\`\`\`

**重要**: 部署命令是**异步**的，立即返回部署 ID，不会等待完成。

### 3. 查询部署状态

部署后必须查询状态：

\`\`\`bash
# 查看最新状态
acornfox status

# 查看指定应用
acornfox status --app my-app

# JSON 格式（便于解析）
acornfox status --json
\`\`\`

**状态字段说明**:
- `status`: `checking` (健康检查中) → `live` (运行中) / `failed` (失败)
- `url`: 应用访问地址 (状态为 `live` 时可用)
- `diagnosis`: 失败时的诊断信息

### 4. 读取诊断信息

当 `status` 为 `failed` 时，查看详细诊断：

\`\`\`bash
acornfox diagnose --json
\`\`\`

**诊断结构**:
\`\`\`json
{
  "stage": "build|start|health|route",
  "code": "具体错误码",
  "message": "人类可读的错误描述",
  "log_excerpt": "相关日志片段",
  "hint": "修复建议"
}
\`\`\`

**常见错误码**:
- `dockerfile_missing`: 缺少 Dockerfile → AI 应在项目中生成 Dockerfile
- `build_failed`: 构建失败 → 检查 `log_excerpt` 中的错误
- `port_not_listening`: 端口未监听 → 检查应用端口配置
- `health_timeout`: 健康检查超时 → 检查应用启动是否正常
- `data/unpersisted_database`: 数据库文件未持久化 → 添加数据卷

### 5. 添加数据库

应用需要数据库时：

\`\`\`bash
# 添加 PostgreSQL
acornfox add postgres --app my-app

# 添加 MySQL
acornfox add mysql --app my-app

# 添加 Redis
acornfox add redis --app my-app
\`\`\`

数据库凭据会自动注入到应用环境变量:
- PostgreSQL/MySQL: `DATABASE_URL`
- Redis: `REDIS_URL`

**重要**: 添加数据库后会自动重新部署应用，需再次查询状态。

### 6. 环境变量

\`\`\`bash
# 设置环境变量
acornfox env set KEY=VALUE --app my-app

# 设置密钥（不会回显）
acornfox env set DB_PASSWORD=secret --secret --app my-app

# 查看环境变量
acornfox env list --app my-app
\`\`\`

### 7. 数据卷

需要持久化数据的目录：

\`\`\`bash
# 添加数据卷
acornfox volume add /app/data --app my-app

# 查看数据卷
acornfox volume list --app my-app
\`\`\`

**自动检测**: Dockerfile 中的 `VOLUME` 会自动添加。

### 8. 生命周期管理

\`\`\`bash
# 停止应用
acornfox stop --app my-app

# 启动应用
acornfox start --app my-app

# 重启应用
acornfox restart --app my-app

# 重新部署（使用当前镜像）
acornfox redeploy --app my-app

# 回滚到上一版本
acornfox rollback --app my-app

# 删除应用（保留数据）
acornfox delete --app my-app

# 删除应用（包含数据）
acornfox delete --app my-app --volumes
\`\`\`

### 9. 日志与监控

\`\`\`bash
# 查看最近日志
acornfox logs --app my-app --tail 100

# 实时跟踪日志
acornfox logs --app my-app -f

# 查看资源使用
acornfox stats --app my-app
\`\`\`

### 10. 域名配置

\`\`\`bash
# 绑定域名（自动申请 HTTPS 证书）
acornfox domain add example.com --app my-app

# 查看域名
acornfox domain list --app my-app

# 解绑域名
acornfox domain remove example.com --app my-app
\`\`\`

**重要**: 
- 域名必须已备案（中国大陆服务器）
- 域名必须已解析到服务器 IP
- 未备案域名会返回提示，但不影响 IP:端口访问

## AI 助手工作流程

### 场景 1: 首次部署（有 Dockerfile）

\`\`\`
用户: "帮我部署这个项目"

1. 检查当前目录是否有 Dockerfile
2. 如果有，执行: acornfox deploy
3. 等待 2-3 秒后查询状态: acornfox status --json
4. 如果 status=checking，告诉用户"正在部署，请稍候"
5. 如果 status=live，告诉用户访问地址
6. 如果 status=failed，读取诊断并修复
\`\`\`

### 场景 2: 首次部署（无 Dockerfile）

\`\`\`
用户: "帮我部署这个 Node.js 项目"

1. 检查当前目录没有 Dockerfile
2. 分析项目结构（package.json, 入口文件等）
3. 生成 Dockerfile（见下方模板）
4. 创建 Dockerfile 文件
5. 执行: acornfox deploy
6. 查询状态并处理结果
\`\`\`

### 场景 3: 部署失败修复

\`\`\`
部署失败，诊断码 = dockerfile_missing

1. AI 应该生成 Dockerfile
2. 重新部署
3. 查询状态

部署失败，诊断码 = build_failed

1. 读取 log_excerpt 找到具体错误
2. 修改 Dockerfile 或代码修复错误
3. 重新部署

部署失败，诊断码 = port_not_listening

1. 检查应用监听的端口
2. 使用 acornfox app set PORT=8080 设置端口
3. 重新部署

部署失败，诊断码 = data/unpersisted_database

1. 识别数据库文件路径（如 /app/data/app.db）
2. 添加数据卷: acornfox volume add /app/data
3. 重新部署
\`\`\`

### 场景 4: 添加数据库

\`\`\`
用户: "我的应用需要 PostgreSQL"

1. 执行: acornfox add postgres --app my-app
2. 告诉用户数据库已添加，连接地址为 DATABASE_URL 环境变量
3. 等待重新部署完成（会自动触发）
4. 查询状态确认
\`\`\`

## Dockerfile 生成模板

### Node.js 应用

\`\`\`dockerfile
FROM node:18-alpine
WORKDIR /app

# 复制依赖文件
COPY package*.json ./

# 安装依赖
RUN npm ci --only=production

# 复制应用代码
COPY . .

# 暴露端口（根据实际端口修改）
EXPOSE 3000

# 启动命令
CMD ["node", "index.js"]
\`\`\`

### Python 应用 (Flask/Django)

\`\`\`dockerfile
FROM python:3.11-slim
WORKDIR /app

# 复制依赖文件
COPY requirements.txt ./

# 安装依赖
RUN pip install --no-cache-dir -r requirements.txt

# 复制应用代码
COPY . .

# 暴露端口
EXPOSE 8000

# 启动命令（根据框架修改）
CMD ["python", "app.py"]
# 或 Django: CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]
# 或 gunicorn: CMD ["gunicorn", "app:app", "-b", "0.0.0.0:8000"]
\`\`\`

### Go 应用

\`\`\`dockerfile
FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY go.* ./
RUN go mod download
COPY . .
RUN go build -o main .

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /app/main ./
EXPOSE 8080
CMD ["./main"]
\`\`\`

## 重要注意事项

### 1. 异步命令模式

**AcornFox 使用异步部署模式**，这意味着：

- `acornfox deploy` 立即返回，不等待完成
- AI 必须主动查询 `acornfox status` 获取结果
- 不要假设部署完成，必须检查状态

**正确流程**:
\`\`\`
deploy → 等待 2-3 秒 → status → 根据状态决定下一步
\`\`\`

**错误做法**:
\`\`\`
❌ deploy → 直接告诉用户"部署完成"（未检查状态）
❌ deploy → 立即 status（太快，还在初始化）
\`\`\`

### 2. JSON 输出解析

所有命令支持 `--json` 标志，返回结构化 JSON：

\`\`\`bash
acornfox status --json
acornfox diagnose --json
acornfox logs --json
\`\`\`

AI 应该**优先使用 JSON 格式**解析输出，而不是解析人类可读文本。

### 3. 应用名称

- 首次部署后，AcornFox 在项目目录创建 `.acornfox` 文件记录应用名
- 后续命令会自动读取应用名，无需 `--app` 参数
- 如果在不同目录操作，必须指定 `--app` 参数

### 4. 数据持久化

**默认行为**: 容器重新部署时，未挂载为数据卷的目录会丢失数据。

**必须持久化的数据**:
- 数据库文件 (SQLite, etc.)
- 上传的文件
- 用户生成的内容

**检测方法**: 
- Dockerfile 中的 `VOLUME` 自动添加
- 部署后如发现未持久化的数据库，会收到 `data/unpersisted_database` 诊断

### 5. 中国大陆特殊情况

**备案要求**:
- 使用域名必须已备案
- 未备案域名无法通过 80/443 端口访问
- IP:端口访问不受备案限制

**网络问题**:
- Docker Hub 可能超时 → 诊断会提示配置镜像加速
- GitHub 克隆可能超时 → 建议使用国内 Git 平台或本地上传

### 6. 常见错误处理

| 错误情况 | AI 应该做什么 |
|---------|-------------|
| 缺少 Dockerfile | 分析项目类型，生成合适的 Dockerfile |
| 构建失败 | 读取日志，修复依赖或配置问题 |
| 端口配置错误 | 检查应用监听端口，使用 `app set` 配置 |
| 健康检查失败 | 检查应用是否真的启动，日志是否有错误 |
| 数据库连接失败 | 检查是否添加了数据库服务，环境变量是否正确 |
| 未持久化数据 | 添加数据卷到相应目录 |

## 调试技巧

### 查看详细日志

\`\`\`bash
# 部署过程日志
acornfox logs --app my-app --tail 200

# 实时跟踪
acornfox logs --app my-app -f
\`\`\`

### 检查应用状态

\`\`\`bash
# 完整状态信息
acornfox status --app my-app --json
\`\`\`

### 查看所有应用

\`\`\`bash
# 列出所有应用
acornfox apps
\`\`\`

## 示例对话

### 示例 1: 成功部署

\`\`\`
用户: 帮我部署这个 Express 项目

AI: 
1. [检查项目] 发现 package.json，这是一个 Node.js Express 项目
2. [检查 Dockerfile] 当前目录没有 Dockerfile
3. [生成 Dockerfile] 我为你生成了一个 Dockerfile
4. [执行部署] 正在部署...
   $ acornfox deploy
5. [查询状态] 等待几秒后查询...
   $ acornfox status --json
   状态: checking (健康检查中)
6. [再次查询] 30秒后...
   $ acornfox status --json
   状态: live ✓
   访问地址: http://your-server-ip:8080

部署完成！你的应用已运行在: http://your-server-ip:8080
\`\`\`

### 示例 2: 修复部署失败

\`\`\`
用户: 部署失败了

AI:
1. [读取诊断]
   $ acornfox diagnose --json
   
   诊断信息:
   - 阶段: build
   - 错误: build_failed
   - 日志: "Error: Cannot find module 'express'"
   
2. [分析问题] 缺少 Express 依赖
   
3. [修复] 我注意到 package.json 中有 express 依赖
   问题可能是 Dockerfile 中的 npm install 命令
   
4. [修改 Dockerfile] 改用 npm ci --only=production
   
5. [重新部署]
   $ acornfox deploy
   
6. [查询状态] 
   $ acornfox status
   状态: live ✓
   
已修复并重新部署成功！
\`\`\`

### 示例 3: 添加数据库

\`\`\`
用户: 我的应用需要连接 PostgreSQL

AI:
1. [添加数据库]
   $ acornfox add postgres --app my-app
   
   PostgreSQL 已添加，正在重新部署应用...
   
2. [等待重新部署]
   数据库连接信息已注入到环境变量 DATABASE_URL
   
3. [查询状态]
   $ acornfox status --json
   状态: live ✓
   
数据库已成功添加！你的应用可以通过环境变量 DATABASE_URL 连接数据库。
\`\`\`

## 帮助与文档

- 命令帮助: `acornfox --help`
- 子命令帮助: `acornfox deploy --help`
- 完整文档: https://acornfox.dev/docs
- GitHub: https://github.com/acornfox/acornfox

---

**提示**: 这是一个实验性的 Skill，随着 AcornFox 的更新可能会有变化。遇到问题时，请查阅最新文档。
