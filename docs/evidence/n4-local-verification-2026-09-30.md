# N4 本地验证与待验收项

日期：2026-09-30。

> 本文是本地阶段过程记录；其“Linux 未执行”状态已经被后续实测更新。最新结论见 [N4 开发机实测与候选收口](n4-devbox-verification-2026-09-30.md)。保留本文用于区分早期模拟验证、未执行项和后续真实证据。

**当时结论：前三项剩余开发工作已完成并通过本地回归；六平台交叉编译通过。N4 整体尚未验收通过。Linux 全量测试和三种数据库真实 Docker 实测未执行，原因是自动权限模式拒绝向开发机传输源码快照。不得将这些未执行项记成通过。**

## 候选与环境

- 工作分支：`acornfox-rebuild-20260929`。本轮未提交 commit，也未推送；包含会话开始前已有的生命周期改动。
- 本地：macOS / arm64，Go `1.25.13`。
- 最终冻结源码清单 SHA-256：`e6b44ea89161b1e071668709dd0e9bca24231d37ea76d39cd8592205d6e50853`。
- 快照、二进制和原始日志：项目根目录下 `.cache/n4-all-fhtng2so/`。
- 快照由 `acornfox/scripts/n4-verify.py all` 产生：覆盖产品 Go 源码、模块文件、嵌入网页、测试及其 fixtures 和验证脚本，排除缓存、二进制、依赖目录及历史 N0 `prototype/`。
- 未仅用 git HEAD 指代候选：本轮工作区有未提交、未跟踪文件，清单记录实际文件内容。

## 剩余五项的真实状态

| 项目 | 状态 | 证据与边界 |
| --- | --- | --- |
| 1. 修复测试编译及集成问题 | 本地完成 | build/vet；state、reconcile、apiserver、client、cli 五包无缓存 race 通过；补删除失败重试、凭据恢复、自动重新部署测试 |
| 2. 补齐日志跟随和网页观测 | 本地完成 | 日志时间游标/边界计数、短轮询、当前和保留密钥脱敏、实时 CPU、容器归属校验；新增 runner observations 测试及网页测试通过 |
| 3. 网页附加服务列表 | 本地完成 | 六种状态、公有网络/环境变量名/数据卷字段，不显示凭据；全部 9 个 Node DOM 用例通过 |
| 4. 开发机实测 | 未执行／权限阻塞 | 只读连接确认 `ubuntu-MS-7B89 / ubuntu`、Docker `29.1.3` 与 Go `1.25.13`；未上传候选源码、未启动独立测试 Docker 或替换现有服务 |
| 5. 六平台编译与全量测试 | 部分完成 | 六平台交叉编译通过；macOS 全量产品测试执行但返回非零；Linux 全量及 Docker 实测仍未执行 |

## 六平台交叉编译

使用同一源码快照，`CGO_ENABLED=0 go build -trimpath ./cmd/acornfox`；每次执行保留实际退出码。

| 平台 | 退出码 | 文件格式 | 二进制 SHA-256 |
| --- | --- | --- | --- |
| Linux amd64 | 0 | ELF x86-64 | `945ff1ecb9cd8882edecc713a3f25475e169585cf2806e1e18704874d5df11b2` |
| Linux arm64 | 0 | ELF aarch64 | `01fd1ec3c2d44199eefac1ca8ac972d2cdf8f1a27ba761103863414294e2bdab` |
| macOS amd64 | 0 | Mach-O x86_64 | `3ab5e457964365a8a732e9da6f1c86259ee138c72e01af9bac7d61cc33d253d6` |
| macOS arm64 | 0 | Mach-O arm64 | `48958b5bd6802faedc18573d9f082df1a3ca64661d2405f7d4fcba5065abda3c` |
| Windows amd64 | 0 | PE32+ x86-64 | `5b1284d3a25da5fa9d237701988dd009f8fe89ed16c6eb00f86d219296be4aee` |
| Windows arm64 | 0 | PE32+ aarch64 | `ffa48b709bc26b72043b0bf69eab7e8a6a11fa6700888ef3dbaf5d08175ae474` |

**交叉编译不等于六个平台实际运行。** 本轮只有原生 macOS arm64 候选运行：`--json version` 返回 `ok=true, version=0.2.0, api_version=1`，并启动真实 server 做下面的本地浏览器验证。Linux、Windows 和其他架构原生运行未执行。

## 当前平台全量产品测试

同一快照执行：

```text
TMPDIR=/tmp go build ./...                             → 退出码 0
TMPDIR=/tmp go vet ./...                               → 退出码 0
TMPDIR=/tmp go test -json -race -count=1 -p 2 ./...     → 退出码 1
```

- 18 个有测试的产品包通过。
- `internal/runner` 的 17 个 Unix socket 往返测试失败，错误均为 `runner: unavailable`。`internal/peer/peer_other.go` 在非 Linux 平台返回 `ErrUnsupportedPlatform`，本地无法完成 Linux 对端 UID 校验，**不能把本轮全量测试记作通过**。
- `TestCaddyIntegration` 和三项实际 Docker 测试被 skip；没有实际运行不能计入验收通过。
- 新增不依赖 Linux socket 的 `TestObservations*` race 测试单独执行通过，覆盖容器归属拒绝、幂等删除、日志帧与游标、CPU/内存计算、停止状态。
- 一次早期快照遗漏了 `tests/fixtures/compatibility/*.json`，造成兼容性测试失败；已修正快照脚本并重跑。最终快照的 compatibility 包通过，失败仅剩 runner。
- 原始完整日志和结构化退出码见 `.cache/n4-all-fhtng2so/{build.log,vet.log,race_tests.log,result.json}`，未用 grep/head 管道替代退出码。

## 网页验证

### DOM 与模拟 API 正向验证

- `node --test internal/console/observations_test.cjs internal/console/addons_test.cjs`：**9/9 通过**。
- Chrome 加本地模拟 API：8 项通过，包括指标数值、日志滚动及键盘焦点跨轮询保持、重复日志、暂停停止请求、附加服务公有字段不泄密、浅色 400px 无横向溢出、无 JS 错误。
- 证据：`/private/tmp/af-n4-ui.ziV8K5/{mock-ui-checks.json,mock-overview-dark.png,mock-addons-light-400.png}`。
- 主会话已查看两张截图。模拟 API 的指标和日志不能当成真实 Docker 数据。

### 真实本地生产服务验证

使用上述最终 macOS arm64 二进制，新的私有 SQLite、Unix API socket、随机回环控制台端口和独立 Chrome profile；没有改动现有服务或用户浏览器 profile。

6 项通过：
1. 实际一次性登录成功，地址栏不保留 token。
2. 无容器时显示指标不可用，不虚构运行指标。
3. 附加服务页面显示公有字段，不包含测试凭据或连接 URL。
4. 两轮轮询后键盘焦点保持。
5. 日志行数及跟随/暂停控件可操作，未上线应用明确显示没有上线版本。
6. 400px 页面不产生横向溢出，无 JS 异常。

- 证据：`/tmp/afn4ui-2y54j747/{browser-result.json,desktop.png,mobile.png}`；主会话已查看最终截图。
- **SQL 中附加服务记录是明确的 UI 测试样本，没有真实 PostgreSQL/MySQL/Redis 容器。不能据此声称数据库连接已验收。**
- 临时生产 server 和 Chrome 已退出；保留私有证据目录供复核。

## 数据与安全边界

- 仅追加 `0005_addon_soft_delete`，未修改迁移 0001～0004。
- `remove addon → add addon` 沿用保留凭据及数据；真实 SQL 存储测试覆盖重新打开后的恢复。
- 附加服务实际删卷失败时继续保留凭据，重试成功后才硬删除记录。
- 删除应用默认仅保留 Docker 卷，SQL 记录及凭据随应用删除；同名重建后若已有数据库卷却缺凭据，返回 `addon_data_orphaned`，不静默生成不能使用的新密码。
- 删除操作与同应用调和串行；资源列表或删除失败不再忽略，应用记录保留供重试，说明部分资源可能已删除。
- 容器操作检查名称与受管/应用标签，使用检查后的 ID 执行。

## 下一验收门槛

用户退出自动权限模式、通过具体源码传输的权限提示后，才继续开发机隔离实测。测试不能让新的空 SQLite 调和器连接现有 Docker daemon，否则全局孤儿清理可能误删已运行应用。需要使用独立测试 Docker 数据目录/socket 与独立 Caddy；保护现有应用和数据，结束后只清理本轮创建的资源。

仍须核验：三种数据库首次初始化及应用真实连接；删除/重加后的数据恢复；实际 volume 删除；生命周期操作；真实日志跟随/脱敏与指标；Linux 全量 race 及显式启用的 Docker 测试。未完成前 N4 保持进行中。
