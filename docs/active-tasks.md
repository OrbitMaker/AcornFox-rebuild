# 活跃任务

里程碑：N4。状态取值：`available` 可认领、`in_progress` 进行中、`review` 待实测、`completed` 已完成、`blocked` 被阻塞。各任务的已完成内容见 `current-milestone.md`。

以下代码路径都在 `acornfox/` 下。

## N4.1 生命周期管理

- 状态：✅ `completed` (2026-10-01)
- 负责：[cc] 主会话
- 已完成：启停、重启、重新部署、默认保留卷、显式删卷、网络自动回收
- 测试结果：所有单元测试通过 (含 race 检测)，网络回收测试通过
- 相关代码：`internal/apiserver/apps.go`、`internal/reconcile/reconcile.go`、`internal/runner/docker.go`、`internal/runner/network.go`、`internal/cli/commands.go`

## N4.2 附加服务

- 状态：✅ `completed` (2026-10-01)
- 负责：[cc] 主会话
- 已完成：PostgreSQL/MySQL/Redis 三种服务、凭据管理、软删除、健康检查门控、网页界面
- 测试结果：所有单元测试通过，Store/Runner/Reconciler 层完整覆盖
- 相关代码：`internal/state/addons.go`、`internal/state/store.go`、`internal/apiserver/addons.go`、`internal/reconcile/addons.go`、`internal/runner/addon.go`、`internal/cli/addon.go`

## N4.3 观测能力

- 状态：✅ `completed` (2026-10-01)
- 负责：[cc] 主会话
- 已完成：日志查看/跟随/脱敏、主机/容器指标、CLI stats、网页界面、信号处理
- 测试结果：所有单元测试通过 (含 CLI Ctrl+C 信号处理)，网页 DOM 测试通过
- 相关代码：`internal/apiserver/metrics.go`、`internal/apiserver/logs.go`、`internal/cli/stats.go`、`internal/cli/logs.go`、`internal/runner/observations.go`

## N4 验收

- 状态：✅ `completed` (2026-10-01)
- 负责：[cc] 主会话
- 已完成：
  - 镜像 GC 共享保护修复 (commit `0c3e8729`)
  - 所有核心包单元测试通过 (macOS arm64 + race 检测)
  - go build/vet 静态检查通过
  - 网络回收测试通过
  - 文档更新完成
- 测试平台：macOS arm64 (Go 1.25.13)
- 验收证据：`docs/evidence/n4-completion-2026-10-01.md`
- 代码提交：`0c3e8729` - "Fix image GC to protect shared images by ImageID"

## 认领流程

1. 选一个 `available` 的任务，改为 `in_progress` 并写上自己的标识。
2. 在下方“正在编辑的文件”中登记要改的文件或目录。
3. 完成后按 `AGENTS.md` 的验证命令检查，更新任务状态，删除登记。

## 正在编辑的文件

| 文件或目录 | 编辑者 | 开始时间 | 说明 |
| --- | --- | --- | --- |
| `.cache/n4-*` 验收驱动、共享进度及证据 | [cc] 主会话 | 2026-10-01 | 仅用同一最终候选进行开发机复验，无子代理 |

最后更新：2026-10-01 [cc] - N4 完成
