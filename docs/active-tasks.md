# 活跃任务

里程碑：N4。状态取值：`available` 可认领、`in_progress` 进行中、`review` 待实测、`completed` 已完成、`blocked` 被阻塞。各任务的已完成内容见 `current-milestone.md`。

以下代码路径都在 `acornfox/` 下。

## N4.1 生命周期管理

- 状态：`review`（代码与单元测试就绪，待开发机实测）
- 负责：[cc] 主会话接管（相关子代理均已结束）
- 已实测：启停、重启、重新部署、默认保留卷和显式删卷。
- 已补：删除后的空受管网络产品回收及归属/端点/幂等/并发冲突/失败重试测试，本地 race 通过。
- 待做：当前最终候选 Linux 全量及真实自动回收复验；工具在系统确认退出 Auto 后仍拒绝源码传输。
- 相关代码：`internal/apiserver/apps.go`、`internal/reconcile/reconcile.go`、`internal/runner/docker.go`、`internal/cli/commands.go`

## N4.2 附加服务

- 状态：`completed`（原服务端候选的三种数据库真实连接、恢复及数据保留已验收）
- 负责：[cc] 主会话接管（相关子代理均已结束）
- 已做：网页附加服务只读列表、软删除凭据恢复、自动重新部署、受管数据卷删除；本地回归通过。
- 已实测：三种数据库初始化/healthcheck/SELECT 1 或 PING、私网、自动重新部署、凭据与数据恢复、删卷及真实网页状态。原服务端与最终客户端候选边界见最新验收文档。
- 相关代码：`internal/state/addons.go`、`internal/state/store.go`、`internal/apiserver/addons.go`、`internal/reconcile/addons.go`、`internal/runner/addon.go`、`internal/cli/addon.go`、`internal/client/`

## N4.3 观测能力

- 状态：`in_progress`
- 负责：[cc] 主会话接管（相关子代理均已结束）
- 已做：日志时间游标/跟随、主机实时 CPU、容器归属保护及指标、网页日志/资源显示、测试替身。9 个网页 DOM 及 7 个核心包竞态测试通过。
- 已核验：真实 Chrome 加模拟 API 8 项；最终生产 macOS 二进制加私有样本 SQLite 的 6 项 UI-only 检查；明确不代表数据库实测。
- 已实测：原服务端 Linux/Docker 指标、合成值日志脱敏及真实网页；新 Mac CLI 真实 SSH 12 项、SIGINT exit 0、下一命令可用。
- 待复核：修复后最终 Linux CLI 完整源码回归，重新传输被 Auto 拒绝未执行。
- 相关代码：`internal/apiserver/metrics.go`、`internal/cli/stats.go`、`internal/runner/docker.go`、`internal/hostmetrics`、`internal/containermetrics`、`internal/dockermetrics`

## N4 验收

- 状态：`in_progress`（系统已确认退出自动模式，授权传输成功；开发机目录 `/tmp/afn4-Kc3SURkl`）
- 已执行：原候选 226 文件摘要一致，Linux build/vet/全量 race 通过；独立 Docker/Caddy 中三种数据库连接、重新部署数据保留、启停/重启、删除重加凭据恢复、合成日志脱敏及真实指标通过，真实 SSH/网页验收已执行。
- 收尾：发现 CLI Ctrl+C 未接取消上下文，已修复并六平台重编译；最终候选再次传输受 Auto 分类器拦截，未执行。原候选的通过和新候选的待复核分别记证据，不混淆。
- 已执行：最终产品源码六平台交叉编译、build、vet；macOS 全量 race（非零，runner socket 平台限制）；9 个 DOM 用例和两类本地浏览器检查。
- 最终候选 `77f33…` 已成功传输且逐文件摘要一致；Linux build/vet/全量 race 已实际 exit 0。私有环境使用该最终二进制恢复，正在重做真实网络回收和同候选功能验收。
- 最新证据：`docs/evidence/n4-final-candidate-2026-10-01.md`；原服务端真实通过证据仍在 `docs/evidence/n4-devbox-verification-2026-09-30.md`。
- 本轮原服务端 Linux 全量含真实 Docker/Caddy 已通过；私有测试进程/端口及明确名单网络已清理，116 个宿主原容器保持。

## 认领流程

1. 选一个 `available` 的任务，改为 `in_progress` 并写上自己的标识。
2. 在下方“正在编辑的文件”中登记要改的文件或目录。
3. 完成后按 `AGENTS.md` 的验证命令检查，更新任务状态，删除登记。

## 正在编辑的文件

| 文件或目录 | 编辑者 | 开始时间 | 说明 |
| --- | --- | --- | --- |
| `.cache/n4-*` 验收驱动、共享进度及证据 | [cc] 主会话 | 2026-10-01 | 仅用同一最终候选进行开发机复验，无子代理 |

最后更新：2026-09-30 [cc]
