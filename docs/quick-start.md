# 快速开始

5 分钟完成首次部署。

## 环境要求

### 服务器端

- **操作系统**: Ubuntu 24.04/22.04/20.04 或 Debian 12/11
- **硬件**: 最低 1 核 1GB，推荐 2 核 2GB+
- **网络**: 公网 IP，开放 22 端口（SSH）
- **权限**: root 或 sudo 权限

### 客户端

- **操作系统**: Windows 10+, macOS 10.15+, Linux (任意发行版)
- **工具**: SSH 客户端

## 安装步骤

### 1. 安装服务器端

SSH 登录你的服务器：

```bash
ssh user@your-server-ip
```

执行安装命令：

```bash
curl -fsSL https://get.acornfox.dev/install.sh | sudo bash
```

**国内服务器**会自动使用镜像加速，无需额外配置。

安装过程约 2-3 分钟，完成后会显示：

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✓ AcornFox 安装完成！
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

管理员令牌:
acf_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

下一步:
  1. 在本地电脑安装 CLI
  2. 配置服务器连接
  3. 打开网页控制台
```

**⚠️ 重要**: 复制并保存管理员令牌，后续需要使用。

### 2. 安装客户端 CLI

在你的本地电脑（Windows/macOS/Linux）执行：

```bash
curl -fsSL https://get.acornfox.dev/install-cli.sh | bash
```

**Windows 用户**：在 PowerShell 或 Git Bash 中执行。

安装完成后验证：

```bash
acornfox version
```

### 3. 配置服务器连接

添加服务器到 AcornFox：

```bash
acornfox target add my-server --ssh user@your-server-ip
```

参数说明：
- `my-server`: 给服务器起个名字
- `user`: 你的 SSH 用户名
- `your-server-ip`: 服务器 IP 地址

**使用 SSH 密钥**：

```bash
acornfox target add my-server --ssh user@your-server-ip --identity ~/.ssh/id_rsa
```

**配置成功**会显示：

```
✓ 连接测试成功
✓ my-server 已添加为默认目标
```

## 部署第一个应用

### 方法 1: 部署本地项目

进入你的项目目录：

```bash
cd /path/to/your/project
```

执行部署：

```bash
acornfox deploy
```

如果项目没有 Dockerfile，AcornFox 会提示你创建。参考：[Dockerfile 模板](#dockerfile-模板)

### 方法 2: 部署 Git 仓库

```bash
acornfox deploy --git https://github.com/username/repo
```

支持的 Git 平台：
- GitHub
- Gitee (国内推荐)
- GitLab
- 任意可通过 HTTPS 匿名克隆的仓库

### 方法 3: 部署 Docker 镜像

```bash
acornfox deploy --image nginx:latest --app my-app
```

## 查看部署状态

部署命令是**异步**的，需要查询状态：

```bash
# 查看状态
acornfox status

# JSON 格式（便于脚本处理）
acornfox status --json
```

**状态说明**：

| 状态 | 含义 | 下一步 |
|------|------|--------|
| `queued` | 排队中 | 等待 |
| `building` | 构建中 | 等待 |
| `checking` | 健康检查中 | 等待，通常 10-30 秒 |
| `live` | 运行中 ✅ | 访问 URL |
| `failed` | 失败 ❌ | 查看诊断 |

### 成功部署

当状态变为 `live` 时：

```bash
acornfox status
```

输出：

```
应用: my-app
状态: live
访问地址: http://your-server-ip:8080
部署时间: 2026-10-01 10:30:00
```

在浏览器中打开访问地址即可。

### 部署失败

当状态为 `failed` 时，查看诊断：

```bash
acornfox diagnose
```

常见错误和修复方法：[故障排查](troubleshooting.md)

## Dockerfile 模板

### Node.js (Express/Koa/Next.js)

```dockerfile
FROM node:18-alpine
WORKDIR /app

# 安装依赖
COPY package*.json ./
RUN npm ci --only=production

# 复制代码
COPY . .

# 暴露端口
EXPOSE 3000

# 启动
CMD ["node", "index.js"]
```

**注意**: 修改 `EXPOSE` 和 `CMD` 为你的实际端口和启动命令。

### Python (Flask/Django/FastAPI)

```dockerfile
FROM python:3.11-slim
WORKDIR /app

# 安装依赖
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# 复制代码
COPY . .

# 暴露端口
EXPOSE 8000

# 启动（根据框架选择）
CMD ["python", "app.py"]
# Django: CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]
# FastAPI: CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
```

### Go

```dockerfile
# 构建阶段
FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY go.* ./
RUN go mod download
COPY . .
RUN go build -o main .

# 运行阶段
FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /app/main ./
EXPOSE 8080
CMD ["./main"]
```

## 下一步

✅ 完成首次部署后，你可以：

1. **管理应用生命周期**
   - 停止/启动/重启应用
   - 查看日志和资源使用
   - 回滚到上一版本

2. **添加数据库**
   - PostgreSQL
   - MySQL
   - Redis

3. **配置域名**
   - 绑定自定义域名
   - 自动申请 HTTPS 证书

4. **集成 AI 工作台**
   - 安装 Skill
   - 通过自然语言部署

详细文档：
- [完整命令参考](commands.md)
- [AI 工作台集成](ai-integration.md)
- [故障排查](troubleshooting.md)

## 常见问题

### 端口被占用

如果看到 `port_conflict` 错误：

```bash
# 查看已使用的端口
acornfox apps

# 为应用指定端口
acornfox app set PORT=8081 --app my-app
acornfox redeploy --app my-app
```

### 数据持久化

数据库文件等需要持久化的数据：

```bash
# 添加数据卷
acornfox volume add /app/data --app my-app
acornfox redeploy --app my-app
```

### 国内网络问题

如果 Docker Hub 拉取镜像超时：

```bash
# 服务器已自动配置镜像加速
# 可以手动验证配置：
sudo cat /etc/docker/daemon.json
```

### 需要帮助？

- 查看命令帮助: `acornfox --help`
- 故障排查: [troubleshooting.md](troubleshooting.md)
- GitHub Issues: https://github.com/acornfox/acornfox/issues
