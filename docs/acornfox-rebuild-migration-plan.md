# AcornFox 单机版整理与简化：迁移清单

> 日期：2026-09-29。状态：负责人已确认采用“保留核心能力、重建外壳”（方案 C）。
> 上位文档：[AcornFox 战略与阶段路线图](acornfox-strategy-roadmap.md) 阶段 0。
> 源码来源：`/Users/a007/.codex/worktrees/acornfox-thin-core-20260926/Open Card`（分支 `codex/acornfox-thin-core-20260926`，工作区含 9 月 16 日之后的全部未提交成果）。

## 1. 目标

在 1～2 周内得到一个干净、可提交、可评审的单机版代码基线：

- 只包含符合战略的代码；
- 运行时为“一个核心进程 + 一个 root 辅助进程”；
- 安装使用安装脚本 + systemd；
- CLI 从一开始按跨平台、令牌认证、部署目标无关来设计；
- 在干净 Ubuntu 24.04 上完成“安装 → 登录 → 部署镜像 → 浏览器访问”。

## 2. 原则

1. **不丢成果：** 迁移前把现工作区完整提交到存档分支；旧仓库、旧数据库、历史证据全部保留，不删除。
2. **只迁不改逻辑：** 已经在真实环境验证过的执行逻辑整体迁入，先保持行为不变，再做接口收敛。
3. **旧代码不迁：** 未列入第 4 节的包一律不迁入新模块。需要时从存档分支查阅。
4. **安全边界保留：** 输入校验、Compose/Dockerfile 危险项拒绝、受管资源归属、密钥不回显、数据卷保留这些行为规则必须迁入并保留测试；只去掉进程间身份校验这一层。
5. **测试按风险：** 迁入包保留与其核心行为相关的测试；删除只针对已移除机制的测试（多进程 IPC、代次、功能包、PG）。

## 3. 目标结构

```text
acornfox/                    新 Go 模块 github.com/acornfox/acornfox（名称待定）
├─ cmd/
│  ├─ acornfox/              CLI（Windows/macOS/Linux）
│  ├─ acornfox-core/         核心服务：HTTP API、网页、SQLite、任务、执行
│  └─ acornfox-helper/       root 辅助进程：白名单宿主操作
├─ internal/
│  ├─ store/                 ← persistence/sqlite
│  ├─ api/                   ← corehttp
│  ├─ app/                   ← application（仅 image_* / source_build_* / task_*）+ contracts
│  ├─ runtime/               ← imageexecution 的执行逻辑（去掉 server/client/attest）
│  ├─ build/                 ← sourcebuildexecution 的执行逻辑 + buildnetwork
│  ├─ gateway/               ← gatewayexecution 的执行逻辑
│  ├─ providers/             registryhttp、image、buildkit、source、acornfoxroute、volume、standalone、capacity
│  ├─ importers/dockerfile/
│  ├─ metrics/               hostmetrics、containermetrics、dockermetrics
│  ├─ auth/
│  └─ helper/                ← hosthelper 中仍需要的白名单操作
├─ web/                      仅 src/core + src/shared
├─ deploy/                   install.sh、systemd 单元、Caddy 配置模板
└─ api/openapi.yaml          CLI / 网页 / 云版共用契约
```

## 4. 逐包处理清单

### 4.1 保留迁入（真实验证过的核心能力）

| 源包 | 去向 | 处理 |
| --- | --- | --- |
| `internal/persistence/sqlite` | `store` | 保留 image/source_build/public_access/audit/outbox/tasks；删除 pack_* 表与迁移；迁移编号重新从 0001 开始（新安装，无兼容负担） |
| `internal/providers/registryhttp`、`image` | `providers` | 原样迁入 |
| `internal/providers/buildkit`、`source` | `providers` | 去掉对 `acornfoxrelease.ParseProductBuildInputsV1` 的依赖，改为读取核心配置 |
| `internal/providers/acornfoxroute` | `providers` | 去掉对 `application` 的反向依赖 |
| `internal/providers/volume`、`standalone`、`capacity` | `providers` | 原样迁入 |
| `internal/importers/dockerfile` | `importers/dockerfile` | 原样迁入 |
| `internal/hostmetrics`、`containermetrics`、`dockermetrics` | `metrics` | 原样迁入 |
| `internal/auth` | `auth` | 增加访问令牌 |
| `internal/buildnetwork` | `build` | 保留构建网络隔离 |
| `internal/artifactio` | 按需 | 只保留 OCI 导出/导入仍在用的部分 |
| `web/src/core`、`web/src/shared` | `web` | 设为唯一入口 |

### 4.2 改造迁入（保留逻辑，重建外壳）

| 源包 | 保留 | 去掉 |
| --- | --- | --- |
| `internal/imageexecution` | runtime、lifecycle、observation、metrics 的执行逻辑 | server/client/protocol/attest/binding（改为核心进程内直接调用） |
| `internal/sourcebuildexecution` | runtime、production、artifact_export、build_logs | server/client/transport 与对端校验 |
| `internal/gatewayexecution` | runtime、source | server/client/peer |
| `internal/application` | `image_*`、`source_build_*`、`task_*`、`contracts/`（去掉 `pack_*`） | `acornfox_*.go`、`controller.go`、`memory.go`（旧 PG 服务端逻辑） |
| `internal/corehttp` | 全部 | 与多角色绑定相关的可用性检查 |
| `internal/hosthelper` | 容器运行和构建确实需要 root 的白名单操作 | 对端 PID/UID 证明 |
| `internal/domain`、`internal/contracts` | 被保留包实际引用的类型 | 其余旧定义（迁移时按编译错误逐个补入） |
| `cmd/acornfox-core` | HTTP、SQLite、任务调度 | 各角色绑定与 authority 服务 |
| `cmd/acornfox` | apps、deploy、image、logs、metrics、operation、status、restart、domain、source-build、login | 旧服务端命令；Cookie+CSRF 会话改为令牌；补 Windows 实现 |
| `internal/install/unified_layout.go` | 目录与账号常量 | — |

### 4.3 不迁入（留在存档分支）

`internal/install`（除 `unified_layout.go`）、`internal/unifiedinstall`、`internal/acornfoxrelease`、`cmd/acornfox-host-*`、`cmd/acornfox-release`、`internal/packmanager`、`internal/packprotocol`、`internal/localpeer`、`internal/corelaunch`、`internal/versionpolicy`、`internal/persistence/postgres`、`cmd/open-card-*`、`internal/controllers`、`internal/healthcheck`、`internal/desktopupdate*`、`internal/darwinlaunch`、`internal/desktopbridge`、`internal/hostprovision`、`internal/dnschange`、`internal/providers/{aliyundns,dnspod,tencentcos,notification,meter,secret,imagegc,registry,dnsfixture,certfixture,publicdns,edgeprobe,caddy,standalonegroup}`、`internal/rules`、`internal/agenttransport`、`internal/migrationpreview`、`internal/pibundle`、`internal/acornfoxcandidate`、`internal/observability`、`internal/importers/compose`、`internal/runtimenetwork`、`packages/container-runtime`、`web/src/acornfox`、`web/src/api`、`migrations/control-plane`、`components/`、`scripts/0x-*`、`desktop/`。

说明：

- `providers/caddy`、`publicdns`、`edgeprobe` 若 TP-10/11 实施时仍需要，届时从存档分支按需迁入；`importers/compose` 在 TP-09（P2）时再评估。
- `acornfoxcandidate`（修复候选验证）与新战略的“AI 修复闭环”相关，但依赖旧服务端；TP-18 设计诊断时再决定是否重做。
- `sourcebuildexecution` 当前依赖 `observability`，迁移时改为只依赖构建日志所需的最小部分。
- 云价格采集 `tools/cloud-pricing` 属于云版方向，不进入单机版仓库。

## 5. 执行顺序

| 步骤 | 内容 | 完成标准 |
| --- | --- | --- |
| M0 | 冻结：现工作区完整提交到 `archive/acornfox-thin-core-20260929`；暂停现有 Codex 在安装链路上的迭代 | 存档分支存在，且与工作区内容一致；台账标记暂停 |
| M1 | 新建模块，迁入 4.1 各包 | Linux 下编译通过，迁入包的原有测试通过 |
| M2 | 改造 4.2：执行逻辑改为核心进程内调用；root 辅助进程只保留白名单操作 | 开发机上镜像部署、启停、数据卷保留、观测与迁移前行为一致 |
| M3 | 安装：`install.sh` + systemd 单元；升级为“备份 SQLite → 替换程序 → 迁移 → 失败回退” | 干净 Ubuntu 24.04 云主机安装成功，完成一次升级 |
| M4 | CLI：令牌认证、Windows/macOS/Linux 编译、部署目标配置、提交即返回 + 查询进度 | 三个平台都能编译，并能对 M3 的服务器完成部署 |
| M5 | 阶段 0 退出验收：干净安装 → 登录 → 部署镜像 → 浏览器访问 | 由未参与开发的人完成 |

M1～M2 按包串行，由单一写入者负责；M4 可以在 M2 完成后与 M3 并行。

## 6. 风险

- **过度删除：** 以编译错误和保留测试为准逐个补回类型，不凭名称判断。
- **行为回退：** M2 用迁移前开发机上已经跑通的镜像和数据卷用例做对照。
- **重复推倒：** 本清单执行期间不接受新的架构变更；新想法进入路线图待定池。

## 7. 执行记录

### M0（2026-09-29 完成）

存档分支 `archive/acornfox-thin-core-20260929`，提交 `577b5605`（614 个文件）。阿里云测试机 `i-REDACTED` 已按负责人指示销毁。

### M1（2026-09-29 完成）

- 分支 `acornfox-rebuild-20260929`（工作区 `战略项目/AcornFox-rebuild`），新目录 `acornfox/`，模块 `github.com/acornfox/acornfox`。仓库根目录只保留 `acornfox/`、`docs/`、`LICENSE`、`NOTICE`、`README.md`，其余代码已删除（在存档分支中可查）。
- 规模：Go 产品代码约 6.8 万行（迁移前 22.2 万行），测试约 3.9 万行；网页约 6.5 千行。`go.mod` 已不再依赖 PostgreSQL 驱动和 Docker SDK。
- 验证（开发机，Go 1.25.13）：`go build ./...`、`go vet ./...`（4 条既有警告）、`go test ./...` 36 个包全部通过；网页 `tsc`、`vite build`、`vitest`（36 个用例）通过。

与第 4 节的差异：

- 包路径暂时保持原 `internal/...`，第 3 节的目录重命名放到 M2 一起做，避免同时改路径和逻辑。
- 多进程相关包（`localpeer`、`packmanager`、`packprotocol`、`corelaunch`、`hosthelper` 的对端校验）和各角色 `cmd` 暂时保留，否则无法编译；M2 移除。
- `internal/install` 只保留目录常量和原子写文件；`internal/acornfoxrelease` 只保留构建输入解析（BuildKit 提供方需要）。
- `internal/observability`、`internal/compatibility` 仍被保留代码引用，暂时保留。
- `application` 只保留 image/source_build/task 相关文件；`acornfoxroute` 改为使用自己的错误值，不再反向依赖 `application`。
- CLI 删除了连接旧服务端的命令（apps、sources、deploy、up、upload、check、plan、status、operation、logs、restart/redeploy/probe、public-access、delivery-source、fix-candidate）。其中本地目录打包上传的实现（旧 `cmd/acornfox/local_project.go`）在存档分支，TP-17 时参考。
- 测试：删除依赖 PostgreSQL、旧服务端、旧 OpenAPI、旧命令和功能包迁移的测试；`corehttp` 中两处基于“0012 迁移尚未注册”的过时断言改为当前行为（已认证的 prepare 返回 201，未知 intent 返回 404）。
- 顺带发现的既有问题见 `acornfox/README.md`“已知问题”。
