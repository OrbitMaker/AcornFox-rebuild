# 单机三平台安装与更新：实施状态

更新日期：2026-09-12。本文记录当前实施与验证边界，详细执行台账位于项目 `.omx/ultragoal/goals.json`；本轮私有证据位于原项目 `.codex-artifacts/acornfox-cross-platform-20260912/`，不随产品发布。

## 范围

本轮只完成 Windows、macOS、Linux 单机安装、启动、产品更新和失败恢复。不接云，不扩展应用商店或宿主 PI 写入能力。普通用户最终应通过安装包和普通语言提示完成操作；当前开发脚本不能视为最终用户安装入口。

复用现有 Linux 后端、PostgreSQL、容器运行与更新事务；Windows 和 Mac 采用受管理的 Linux 环境。Linux 测试包含 Ubuntu 24.04 与 Debian 13。不得把测试工具就绪写成产品已安装。

## 实际测试环境

| 环境 | 已验证事实 | 尚未验证 |
| --- | --- | --- |
| Ubuntu | 开发机上的独立 Ubuntu 24.04.4 amd64 虚拟机，2 CPU / 4 GiB，SSH 可达 | 新产品候选首装、重启、更新、真实样例应用 |
| Debian | 开发机上的独立 Debian 13 amd64 虚拟机，2 CPU / 4 GiB，SSH 可达 | PostgreSQL 16 安装来源及产品首装、更新 |
| Mac | 本机 macOS 26.4 / Apple Silicon；隔离 Lima 2.2.0 / VZ Ubuntu ARM guest，2 CPU / 4 GiB，回环 8080 转发已验证 | 产品 ARM 候选、Mac 安装包和宿主更新 |
| Windows | 既有 QEMU Windows VM 正运行，现为 8 CPU / 6 GiB；本轮尚未更改它 | 无损自动化通道、WSL2、2 CPU / 4 GiB、产品安装与更新 |

Lima 是开发验收工具，不是已确定的用户端依赖。ARM guest 已安装构建工具并完成运行组件构建，尚未安装产品。开发机其他业务虚拟机没有变更。本机尚无可用 Developer ID 签名身份，公开分发签名未验收。

## 已实现及已验证的模块

- `scripts/acornfox-desktop/preflight.py` 只观察宿主条件，不把虚拟化指令存在当成运行环境可用；安装状态保持 `not_checked`。
- `prepare-vm.py` 仅生成本任务虚拟机计划，校验镜像摘要、公钥、存储路径和名称冲突；Ubuntu/Debian 计划使用 2 CPU / 4 GiB，包含实际 Debian 启动所需的 VGA。12 个相关测试已通过。
- Linux amd64/arm64 的运行配置原子发布已使用各自正确的 `renameat2`，保留不覆盖目标的约束；两种 CPU 的真实 Linux 内核测试已通过。
- 发布器目标架构、Go 构建信息、ELF CPU 类型与候选绑定使用同一架构事实；ARM 的错架构拒绝和真实候选导出不覆盖测试已通过。非 Linux 导出仍拒绝。
- 本地控制台模式明确为 `local_loopback`，仅接受 `http://127.0.0.1:8080`；公网 HTTPS 模式保留原行为。本地 Setup、登录、密码修改、会话失效和四个 Web 客户端的 CSRF 路径已有定向测试。
- `internal/acornfoxsetup` 生成和严格验证本地 7 个文件，不生成 `edge.json`；配置重绑保留证书、密钥和 Setup Token。运行配置和恢复复用同一份受摘要绑定的 Intent，不新增数据库。
- 安装器在包管理或账号修改前校验模式和参数。本地模式禁用公网 Edge 与现有依赖公网 Edge 的 Healthcheck Timer。`wait-local-ready` 使用包内 Go Helper 等待后台和 8080 Setup API 就绪，不依赖 Curl。
- 升级测试已覆盖失败回退、重试和配置保留。真实服务适配器必须在本地模式完全跳过 Edge 的停止、启动和探活；仅有宽松 Fake 的通过不能代替目标机验证。
- `internal/desktopupdate` 已完成签名索引、版本/序列检查、HTTPS 下载、大小与摘要核验、私有暂存和不覆盖发布。Mac race、Ubuntu/Debian amd64 和 ARM Linux 实际运行已通过；Windows仅完成编译检查。此包尚未接入版本激活。

此前 Claude Code 环境中的升级测试失败已定位为执行器继承日志保护用的 `umask 077`，影响测试样本权限。执行器子进程现使用 `022`，私有日志仍单独保护；不因此放宽产品校验。

## 本地运行约束

内部 Caddy 使用既有 `deploy/caddy/acornfox.Caddyfile.example`，安装位置为 `/etc/acornfox/Caddyfile`，受候选摘要绑定。该模板已以真实 Caddy 2.11.4 验证向后台转发正确的 Host、Forwarded Host 和 HTTP Scheme。不能安装后手工覆盖为另一份模板。

Web 构建资源由内部 Caddy 从 `/opt/acornfox/current/web/dist` 提供，API 转发到回环 18481；不应描述为前端资源已嵌入 Go 二进制。

本地模式可以不配置公网 DNS，此时控制台可以启动，但公开 Git 导入仍会按策略拒绝。需要 Git 导入的真实验收应提供两个有效 Resolver。首装与升级的健康检查应覆盖 18481 的 Health/Ready 以及 8080 的 Setup API，拒绝 unavailable、HTML、重定向和不兼容响应。

## 下一步验收

1. 冻结审核后的内部候选，在新的 Ubuntu 2 CPU / 4 GiB 虚拟机进行首装、Setup/Login、样例应用、重启、升级和注入失败恢复。
2. 接通 ARM 官方运行资产、PI 分架构清单与发布准备脚本，再验证完整 ARM 候选。已有 ARM 组件下载与 runc 两次构建一致证据不能代替候选验收。
3. 完成 Debian 的 PostgreSQL 16 与系统检查适配，保留原有校验。
4. 完成 Mac/Windows 宿主入口、安装包装，以及宿主与 Linux 后端的更新协作。
5. 验证断网、坏包、空间不足、端口冲突、宿主重启和更新失败后的恢复。最后才判断三平台可安装与完整自更新是否通过。
