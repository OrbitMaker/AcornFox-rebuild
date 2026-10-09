# AcornFox

**让 AI 一句话部署你的应用**

AcornFox 是一个开源的应用部署平台，让你在自己的 Linux 服务器上轻松部署和管理应用。

[![License](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/go-1.21+-00ADD8.svg)](https://go.dev)

## ✨ 特性

- 🚀 **一键部署** - 本地目录、Git 仓库或 Docker 镜像
- 🤖 **AI 集成** - 通过 AI 工作台自然语言部署
- 🔍 **智能诊断** - 部署失败时返回结构化诊断，AI 自动修复
- 🗄️ **附加服务** - 一键添加 PostgreSQL/MySQL/Redis
- 📊 **监控指标** - 实时查看日志和资源使用
- 🌐 **自动 HTTPS** - 已备案域名自动申请 SSL 证书
- 🇨🇳 **国内优化** - 镜像加速、超时诊断

## 🎯 适用场景

AcornFox 专为以下场景设计：

- **个人开发者**: 在自己的云服务器上部署个人项目
- **小团队**: 快速部署测试环境和演示应用
- **AI 用户**: 通过 AI 助手自然语言部署应用
- **学习实验**: 学习 Docker、容器编排和应用部署

## 🚀 快速开始

### 推荐：把一句话发给 AI 工作台

准备一台能 SSH 登录的 Linux 服务器（Ubuntu 24.04/22.04/20.04 或 Debian 12/11），在 Claude Code、Codex 等 AI 工作台里发送：

```text
请安装 AcornFox Skill：下载 https://acornfox.com/skill/SKILL.md ，保存为你 skills 目录下的 acornfox/SKILL.md（Claude Code 是 ~/.claude/skills，Codex 是 ~/.codex/skills），然后按这个 Skill 把当前项目部署到我的服务器。
```

AI 会先安装 Skill，再由 Skill 分别判断你的电脑和服务器在国内还是海外，选择 Gitee 或 GitHub 下载源，装好 CLI 与服务端，然后部署。

> **云服务器安全组**：应用通过 `http://服务器IP:端口` 访问，端口在 18810-18899 之间分配。请在云厂商控制台的安全组中放行入方向 TCP 18810-18899；绑定域名启用 HTTPS 还需放行 80 和 443。

### 手动安装

#### 1. 安装服务器端

```bash
# 中国大陆服务器（Gitee 镜像）
curl -fsSL https://gitee.com/VIP13390/AcornFox-rebuild/raw/main/scripts/install/install.sh | sudo bash
# 其他地区
curl -fsSL https://github.com/OrbitMaker/AcornFox-rebuild/releases/latest/download/install.sh | sudo bash
```

安装完成后会显示管理员令牌，请妥善保存。

#### 2. 安装客户端 CLI

```bash
# 中国大陆
curl -fsSL https://gitee.com/VIP13390/AcornFox-rebuild/raw/main/scripts/install/install-cli.sh | bash
# 其他地区
curl -fsSL https://github.com/OrbitMaker/AcornFox-rebuild/releases/latest/download/install-cli.sh | bash
```

#### 3. 配置服务器连接

```bash
acornfox target add my-server --ssh user@your-server-ip
```

#### 4. 部署你的第一个应用

```bash
cd your-project
acornfox deploy
```

部署后查询状态：

```bash
acornfox status
```

当状态变为 `live` 时，访问返回的 URL 即可。

## 🤖 AI 工作台集成

Skill 是使用 AcornFox 的入口：首次使用时由它安装 CLI 与服务端，之后负责部署、读诊断并修复、管理数据库和生命周期。

### 安装 Skill

- **还没有 CLI**：把「快速开始」里那句话发给 AI 工作台，AI 会从 `https://acornfox.com/skill/SKILL.md` 下载 Skill。
- **已有 CLI**：`acornfox skill install` 安装与 CLI 同版本的 Skill。

| 工作台 | 方式 |
| --- | --- |
| Claude Code | 自动安装到 `~/.claude/skills/acornfox/` |
| Codex | 自动安装到 `~/.codex/skills/acornfox/` |
| 其他工具 | `acornfox skill install --dir 目录`，或 `acornfox skill print` 输出内容 |

### 使用示例

```
你: 帮我把这个项目部署到我的服务器

AI: 已生成 Dockerfile，开始部署。
    [health] 容器启动后退出或反复重启
    日志片段：Error: DATABASE_URL is not set
AI: 诊断显示缺少数据库，添加 PostgreSQL 并重新部署。
    ✓ 已上线 http://服务器IP:18810
```

## 📖 核心命令

```bash
# 部署
acornfox deploy                              # 部署当前目录
acornfox deploy --git https://github.com/... # 部署 Git 仓库
acornfox deploy --image nginx:latest         # 部署 Docker 镜像

# 状态
acornfox status                              # 查看应用状态
acornfox apps                                # 列出所有应用
acornfox logs --app my-app -f               # 查看实时日志

# 生命周期
acornfox stop/start/restart --app my-app    # 启停应用
acornfox redeploy --app my-app              # 重新部署
acornfox rollback --app my-app              # 回滚到上一版本
acornfox delete --app my-app                # 删除应用

# 附加服务
acornfox add postgres --app my-app          # 添加 PostgreSQL
acornfox add mysql --app my-app             # 添加 MySQL
acornfox add redis --app my-app             # 添加 Redis

# 域名
acornfox domain add example.com --app my-app # 绑定域名（自动 HTTPS）
```

## 🏗️ 架构设计

AcornFox 采用简洁的三层架构：

- **AcornFox** - 状态管理和协调
- **Docker** - 容器运行时
- **Caddy** - HTTP 路由和 HTTPS

设计原则：
- **状态与执行分离** - server 无 Docker 权限，runner 只接受类型化请求
- **调和而非编排** - 记录"应该是"，让 runner 自动收敛
- **应用独立性** - 应用由 Docker 管理，AcornFox 崩溃不影响运行中的应用
- **诊断即产品** - 失败时返回结构化诊断，AI 可自动修复

## 🌏 中国大陆特别说明

### 域名与备案

- **已备案域名**: 自动申请 HTTPS 证书，通过 80/443 端口访问
- **未备案域名**: 绑定时会收到提示，但可通过 IP:端口正常访问
- **IP 访问**: 不受备案限制，始终可用

### 网络优化

安装脚本自动检测中国环境并配置：
- APT 使用阿里云镜像源
- Docker 使用阿里云/腾讯云镜像加速
- Caddy 通过 GitHub 代理下载

手动指定：
```bash
# 强制使用中国镜像源
sudo bash install.sh --china

# 强制使用国际源
sudo bash install.sh --global
```

## 📚 文档

- [快速开始](docs/quick-start.md)
- [常见问题](docs/quick-start.md#常见问题)
- [AI 工作台 Skill](skills/acornfox/SKILL.md)
- [架构设计](docs/architecture.md)

## 🛠️ 升级

```bash
# 服务器端升级
curl -fsSL https://github.com/OrbitMaker/AcornFox-rebuild/releases/latest/download/upgrade.sh | sudo bash
# 中国大陆：
curl -fsSL https://gitee.com/VIP13390/AcornFox-rebuild/raw/main/scripts/install/upgrade.sh | sudo bash

# 客户端升级
curl -fsSL https://github.com/OrbitMaker/AcornFox-rebuild/releases/latest/download/install-cli.sh | bash
```

升级过程自动：
- 备份当前版本和数据库
- 执行 SQLite 迁移
- 升级失败自动回滚
- **应用容器不受影响**

## 🤝 贡献

欢迎贡献代码、文档或提出建议！

1. Fork 本仓库
2. 创建特性分支 (`git checkout -b feature/amazing`)
3. 提交更改 (`git commit -m 'Add amazing feature'`)
4. 推送到分支 (`git push origin feature/amazing`)
5. 创建 Pull Request

请阅读 [贡献指南](CONTRIBUTING.md) 了解详情。

## 📜 许可证

本项目采用 AGPL-3.0 许可证 - 详见 [LICENSE](LICENSE) 文件。

## 🙏 致谢

AcornFox 站在巨人的肩膀上：

- [Docker](https://www.docker.com/) - 容器运行时
- [Caddy](https://caddyserver.com/) - HTTP 服务器和自动 HTTPS
- [SQLite](https://www.sqlite.org/) - 嵌入式数据库
- 所有贡献者和用户

## 📮 联系方式

- 问题反馈: [GitHub Issues](https://github.com/OrbitMaker/AcornFox-rebuild/issues)
- 文档: https://github.com/OrbitMaker/AcornFox-rebuild/tree/main/docs

---

**让部署变简单，让 AI 来帮忙** 🦊
