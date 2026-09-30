# N4 最终候选：收口代码已补，开发机复验待权限

日期：2026-10-01。

**结论：空受管网络回收及 CLI Ctrl+C 两项修复均已实现，最终合并候选六平台编译、build、vet 和相关本地竞态回归通过。最终源码传输仍被工具 Auto 分类器拒绝，未执行；该候选的 Linux 完整回归和真实网络自动回收复验尚未执行，N4 不标最终验收通过。**

## 最终候选

- 产品源码清单 SHA-256：`77f33e45712dc3480c6d9a21c2971483773ddf9cc9dcfec06bb55398519ad094`。
- 快照及完整结果：`.cache/n4-all-cryrc5lx/`。
- 未提交 commit，未推送。

| 平台 | 编译退出码 | 二进制 SHA-256 |
| --- | --- | --- |
| Linux amd64 | 0 | `571e88ca65ba9a68be3272055e1390f034055fbc25d35d069350a961d96f798e` |
| Linux arm64 | 0 | `b18f316406dbc50b9592b3afb45c7125652980ed226ed8f22436d685d4ccb996` |
| macOS amd64 | 0 | `2845671227475c5c2fab1a01f27aec5caf9dbde2e90739e0b6c0cb6eb25b89cd` |
| macOS arm64 | 0 | `e34c4b8ca3b3d96541c0b084bcddce2c12b0891af2c65aee02548654ebd8f862` |
| Windows amd64 | 0 | `e3b17037a1b51a04037bddc36861906e3d0b1a0fe420a4968a21fcb4c2c39edd` |
| Windows arm64 | 0 | `3f0dccb5547c959ee332bb3dde9a95f719387a9dcfc79ff309d084018295349a` |

交叉编译不代表六个平台原生运行。

## 网络回收代码

- 新增 typed per-app `NetworkRemover`、runner 路由及客户端方法；调用方只给应用名，不能指定任意网络或强制断开端点。
- 删除应用在同应用串行锁内，移除受管容器/按选项处理卷后，再删除空网络；成功后才删应用记录。
- 要求网络名 `af-<app>`、`acornfox.managed=1`、`acornfox.app=<app>` 全部匹配。
- 仍有端点、缺失 ID、无标签或其他应用标签时拒绝；没有网络及删除时已消失视为幂等成功。
- 实际删除使用检查后的网络 ID，避免名称在检查后被替换。
- 网络回收失败返回 `network_removal_failed`，说明应用记录仍保留，部分容器/卷可能已删除，允许检查后重试。
- 创建容器时也拒绝复用同名外来网络；并发创建冲突后重新检查标签，不把 conflict 直接视为成功。

相关文件：`internal/runner/network.go`、`network_test.go`、`server.go`、`docker.go`；`internal/apiserver/apps.go`、`network_cleanup_test.go` 与接口/测试替身。

## 实际本地验证

- `go build ./...`、`go vet ./...`：通过。
- `TMPDIR=/tmp go test -race -count=1` 对 cmd/acornfox、apiserver、client、cli、reconcile、state：通过。
- `internal/runner -run '^TestNetwork'` race：通过，覆盖归属、连接端点、缺失、按 ID 删除、同名冲突、并发冲突、typed 路由与请求校验。
- 应用 API 默认保留卷仍回收网络，网络失败保留记录并重试成功：通过。
- 本地全量产品 race 实际返回 1：只有已有 runner Linux 对端 UID 依赖的 socket 测试失败。没有把这个结果记为全量通过。

## 与此前真实实测的区别

此前 [2026-09-30 开发机证据](n4-devbox-verification-2026-09-30.md) 的原服务端候选确实通过 Linux 全量、真实 Docker/Caddy、三数据库、数据保留、真实网页；CLI 中断修复后的 Mac 候选也真实 SSH 通过。

但这些记录不能代替当前 `77f33…` 完整候选的最终 Linux 验证。旧记录中的“空网络由驱动清理”是当时实际行为；如今自动回收代码已实现，只是尚未进行当前版本的实机复验。

## 当前阻塞与环境状态

用户确认切换权限模式，系统也明确通知 `Exited Auto Mode`。然而针对最终快照的 tar→SSH 调用仍返回 Auto classifier 的 Data Exfiltration 拒绝，命令未执行，远程 `/tmp/afn4-Kc3SURkl/candidate-final` 未由本轮传输创建。

不通过分片、换工具、换代理或改编码绕过；不自行改权限配置，也不再假定用户没有切换。需要会话宿主的工具权限状态与已确认的模式一致后，审查并执行最终传输。

旧私有测试进程和端口保持已关闭，116 个宿主原容器保护记录仍有效。最终验收驱动已准备好恢复本轮私有 Docker 数据目录，用当前候选重新测试，不会连接系统 Docker 来做孤儿清理。

## 继续验收门槛

1. 最终快照传输后逐文件摘要核对。
2. 当前候选 Linux build/vet/全量 race、显式 Docker/Caddy 测试与 CLI 实际 Ctrl+C。
3. 默认保留卷及显式删卷时，应用网络由产品自动移除；外来标签/端点保留，失败可重试。
4. 用同一候选记录新结果、保护基线及清理证明，再将 N4 标为通过。
