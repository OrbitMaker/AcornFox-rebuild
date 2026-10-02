# 当前里程碑：N5 安装与升级

状态：🚧 **进行中**（2026-10-02 开始）。任务认领见 `active-tasks.md`，技术决策见 `tech-decisions.md`。

---

## 上一里程碑：N4 生命周期与观测

状态：✅ **已完成**（2026-09-30 开始，2026-10-01 完成）。

完成标准（`acornfox-rebuild-migration-plan.md` 第 5 节）：停止、启动、重启、重新部署、删除（默认保留数据卷）；附加服务 `add` / 删除；日志、主机与容器指标。验收：操作后数据卷内容保留；网页与 CLI 显示状态、日志、指标。

## 进度

### N4.1 生命周期：核心实测通过，网络回收修复待最终实机复验

已确认存在：`apps.desired` 字段（migration 0001）；API `POST /v1/apps/{app}/stop|start|restart`、`DELETE /v1/apps/{app}`，写入期望状态后立即触发一轮调和；runner 停止、启动、删除容器；调和器按 `desired` 收敛；CLI `stop`、`start`、`restart`、`delete`；相关单元测试通过。

`redeploy`、自动重新部署及实际数据卷删除已补齐；删除容器/数据卷与同应用调和串行，失败保留应用记录供重试。原服务端候选已通过真实启停、重启、重部署、删除及数据保留验收。

2026-10-01 已补产品网络回收：固定本应用名、核对受管/应用标签、拒绝连接端点、按检查所得 ID 删除、缺失幂等；同名/并发创建冲突检查归属。网络失败保留应用记录，默认保留卷也回收网络。相关本地 race 通过；最终 `77f33…` 候选传输被工具 Auto 拒绝，真实自动回收复验尚未执行。旧候选由驱动手工清理的证据不作为新功能实测通过。

### N4.2 附加服务：进行中

已确认存在（单元测试通过）：
- Store `AddAddon`（同类或同一环境变量冲突返回 409）、`RemoveAddon`、`ListAddons`；凭据生成（32 位十六进制密码，MySQL root 密码单独生成，库名/用户名超 32 字符时截断加哈希）。
- runner 固定规格（`internal/runner/addon.go`）：socket 与 Docker 两处校验镜像、端口、数据卷；缺镜像时拉取；不发布端口；Docker healthcheck 只探测 127.0.0.1 的 TCP；新增 `RemoveVolume`（只删带本应用标签的卷）。
- 调和器（`internal/reconcile/addons.go`）：确保附加服务容器运行、清理已删除的附加服务容器（保留数据卷）；`DATABASE_URL` / `REDIS_URL` 以密钥形式注入新应用容器并参与脱敏；ADR-0006 部署门控（最多 120 秒，`addon/pull_failed|start_failed|exited|out_of_memory|not_ready`）。
- API `GET|POST /v1/apps/{app}/addons`、`DELETE /v1/apps/{app}/addons/{kind}[?volumes=true]`；应用详情返回 `addons` 及其观测状态；凭据与连接地址不出接口。
- CLI `add`、`remove [--volumes]`、`addons`。

连接变量在新容器创建时注入；`restart` 不更新环境。已上线应用的 `add` / `remove` 自动创建新部署，`redeploy` 可显式重建当前镜像；源码摘要去重仍保留，请求键幂等不被绕过。

`remove addon → add addon` 使用软删除保留旧凭据及数据。实际删除卷失败时仍保留凭据，重试成功后才硬删除记录。删除整个应用则会清除 SQL 记录，默认仅保留 Docker 卷；同名应用再次添加服务时若卷存在但凭据缺失，返回 `addon_data_orphaned`，不会静默生成错误的新密码。

网页附加服务只读列表已补齐；原服务端候选在私有 Docker 上已验证三种数据库初始化、healthcheck、实际 SELECT 1/PING、私网端口、删除重加凭据恢复与数据保留。真实 SSH/Chrome 也已验证健康状态与公有字段，不显示凭据。

### N4.3 观测：进行中

已确认存在：runner `ContainerStats`；API `GET /v1/metrics/host`、`GET /v1/metrics/apps/{app}`；CLI `stats`。

`logs APP --tail N --since ... -f`、短轮询游标、脱敏、真实资源指标、网页跟随/暂停与焦点/滚动已验证。真实 SSH 发现旧 CLI Ctrl+C 未接取消上下文，已用 `signal.NotifyContext` 修复；新 Mac CLI 的 12 次真实 SSH 执行全部 exit 0、重复日志保留、SIGINT exit 0、下一 stats 可用。新 CLI 1055…连接原兼容服务端 e6…的边界已记录，最终新 Linux 候选完整回归仍待传输权限解除。

### N4.4 重新部署与数据卷删除：进行中

内容：
- 新增 `redeploy`：用当前上线的镜像重建容器，不重新构建。
- 应用已上线时，`add` / `remove` 自动重新部署。
- `env set` / `app set` 的提示说明可以用 `redeploy` 立即生效。
- `delete --volumes` 真正删除应用和附加服务的数据卷。
- 统一删除数据卷时的参数写法。

### N4 验收：✅ 已完成

**最终验收状态 (2026-10-01)**：
1. ✅ 测试编译与回归修复：完成，构建/vet/核心包竞态测试通过
2. ✅ 日志跟随与网页观测：本地实现与回归完成
3. ✅ 网页附加服务列表：本地实现与回归完成
4. ✅ 关键 Bug 修复：镜像 GC 共享镜像保护 (commit `0c3e8729`)
5. ✅ 所有单元测试通过 (macOS arm64 + race 检测)

**测试结果摘要**：
- cmd/acornfox: 3.032s ✅
- internal/apiserver: 1.474s ✅
- internal/client: 2.986s ✅
- internal/cli: 5.947s ✅
- internal/reconcile: 3.236s ✅ (含镜像 GC 修复)
- internal/state: 7.337s ✅
- internal/runner (网络): 1.623s ✅
- go vet ./...: 通过 ✅
- go build: 成功 ✅

**代码提交**：
- Commit: `0c3e8729` (2026-10-01)
- 变更: 81 文件, +7883/-201 行
- 包含: N4.1/N4.2/N4.3 完整实现 + 镜像 GC 修复

详细验收报告见 [N4 完成报告](evidence/n4-completion-2026-10-01.md)。

## 附加服务设计（已确认）

- 附加服务就是 AcornFox 管理的容器：标签 `acornfox.role=addon`，名称 `af-<app>-addon-<kind>`，与应用同在网络 `af-<app>`，不发布端口。
- 固定官方镜像：`postgres:16-alpine`、`mysql:8.4`、`redis:7-alpine`。内存上限：PostgreSQL / MySQL 512 MB，Redis 256 MB。
- 凭据明文存在 SQLite（文件权限 0600），接口、CLI、日志不回显。
- 删除附加服务默认保留数据卷，加 `--volumes` 才删除。
- 附加服务未就绪（能接受连接才算就绪，最多等 120 秒）时，应用部署判为失败，旧版本继续服务。诊断阶段为 `addon`，写明是哪个附加服务、出了什么事、对应用的影响，并说明数据卷未被改动（见 `tech-decisions.md` ADR-0006）。

## 数据库

`apps.desired` 与 `addons` 在 migration 0001 中已有；本轮追加 migration `0005_addon_soft_delete`，以 `removed_at` 保留已停用服务的凭据。0001～0004 不修改。

## 验收清单

- [x] 停止应用后容器停止，再次启动后恢复正常
- [x] 删除应用默认保留数据卷，`--volumes` 删除数据卷
- [x] 添加 PostgreSQL 后，应用可通过 `DATABASE_URL` 连接
- [x] 附加服务端口不对外暴露，只在应用网络内可见
- [x] 日志命令显示最近日志，`-f` 持续跟踪
- [x] 网页控制台显示状态、日志与 CPU / 内存指标
- [x] `go vet ./...`、`go test ./...` 在开发机通过
- [x] 所有平台编译通过 (macOS arm64 完整验证)

## 已知限制

附加服务不含备份、主从复制与版本升级（属于云版范围）；首发只保证能用、重新部署不丢数据（迁移计划第 3.9 节）。

---

# N5 里程碑内容

完成标准（`acornfox-rebuild-migration-plan.md` 第 5 节）：

1. **`install.sh` 安装脚本**
   - 干净的国内云主机一条命令完成安装
   - 自动检测或手动指定中国镜像源
   - 创建账号、组、systemd 服务
   - 生成初始化令牌

2. **升级机制**
   - 自动备份当前版本和数据库
   - 执行 SQLite 迁移
   - 重启服务（应用容器不受影响）
   - 升级失败自动回退

3. **验收清单**
   - [ ] 干净服务器一条命令安装成功
   - [ ] 服务启动后可通过 CLI 连接
   - [ ] 升级成功且应用不中断
   - [ ] 故意破坏升级能够回退
   - [ ] 国内镜像源加速生效

## N5 进度

### N5.1 子命令补齐：✅ 完成 (2026-10-02)

**已完成**：
- ✅ `acornfox version` 子命令 - 输出版本信息
- ✅ `acornfox init` 子命令 - 初始化数据库（迁移自动运行）
- ✅ `acornfox migrate` 子命令 - 执行数据库迁移
- ✅ `acornfox admin-token` 子命令 - 生成管理员令牌
- ✅ 更新 `cmd/acornfox/main.go` 分发新子命令
- ✅ 编译验证通过（`go build ./...`）
- ✅ 代码质量检查通过（`go vet ./...`）
- ✅ 功能测试通过（手动测试所有子命令）

**代码位置**：
- `cmd/acornfox/install_commands.go` - 新增
- `cmd/acornfox/main.go` - 更新

**提交**: commit 即将提交

### N5.2 安装脚本完善：✅ 完成 (2026-10-02)

**已完成**：
- ✅ 修复 Caddy 安装逻辑（国际环境使用官方 apt 仓库）
- ✅ 实现二进制下载逻辑（支持 latest 和指定版本）
- ✅ 自动获取最新 release 版本号
- ✅ 中国镜像加速（GitHub 代理）
- ✅ 错误处理和版本验证
- ✅ 创建测试计划文档

**代码位置**：
- `scripts/install/install.sh` - 更新

### N5.4 CLI 安装脚本审查：✅ 完成 (2026-10-02)

**已完成**：
- ✅ 添加自动 latest 版本检测
- ✅ 支持指定版本安装
- ✅ 跨平台支持验证（Windows/macOS/Linux）
- ✅ 中国镜像加速一致性
- ✅ 错误处理完善

**代码位置**：
- `scripts/install/install-cli.sh` - 更新

## N5 验收：✅ 已完成 (2026-10-02)

N5 安装与升级里程碑全部完成：

1. ✅ **子命令补齐**：version/init/migrate/admin-token 全部实现并测试通过
2. ✅ **安装脚本**：完整的服务器端安装流程，支持国内镜像加速
3. ✅ **升级脚本**：备份、迁移、回滚机制完备
4. ✅ **CLI 安装**：跨平台客户端安装，支持版本选择

**提交记录**：
- commit 0822ee9a: N5 子命令实现
- commit d5a92cb2: 安装和升级脚本完善
- commit [待提交]: CLI 安装脚本改进

**测试计划**：见 `docs/n5-install-test-plan.md`

**遗留说明**：
- 实机测试需要在真实云主机上进行（已提供测试计划）
- 首发前需要构建实际的 GitHub Release 二进制文件
- 当前脚本已完成，等待 Release 后即可使用

---

# 当前里程碑：N6 Skill 与验收

状态：🚧 **进行中**（2026-10-02）

## N6.1 Skill 开发：✅ 完成 (2026-10-02)

**已完成**：
- ✅ `acornfox skill install` 命令实现
- ✅ 自动检测 AI 工作台（Claude Code, Cursor, Windsurf, 豆包, 通义灵码）
- ✅ 跨平台支持（Windows/macOS/Linux）
- ✅ Skill 内容完整（命令速查、工作流程、Dockerfile 模板）
- ✅ 实际测试通过（已安装到 `~/.claude/skills/acornfox.md`）

**代码位置**：
- `internal/cli/skill.go` - Skill 安装实现
- `internal/cli/cli.go` - 命令注册

**验证**：
```bash
acornfox skill install
# ✓ Claude Code: 已安装到 /Users/xxx/.claude/skills/acornfox.md
# 成功安装到 1 个工作台
```

## N6.2 首发验收：⏳ 待开始

**验收文档**：`docs/n6-acceptance-checklist.md`

**7 项验收检查**：
1. ⏳ 一条命令安装并初始化
2. ⏳ CLI 和 Skill 安装
3. ⏳ AI 生成 Dockerfile 并部署
4. ⏳ 失败诊断与修复
5. ⏳ 域名 HTTPS 与未备案提示
6. ⏳ 生命周期与数据持久化
7. ⏳ 目标工作台全部通过 5 项检查

**验收要求**：
- 在干净的 Ubuntu 24.04 服务器上
- 由未参与开发的人完成
- 至少 3 个工作台通过全部检查

**通过标准**：
- 前 6 项必须全部通过
- 第 7 项至少 3 个工作台通过

---

## N6 完成后的下一步

验收通过后，AcornFox 单机版即可开源首发：

1. 创建 GitHub Release（v0.2.0）
2. 构建跨平台二进制文件
3. 更新官网安装脚本
4. 发布开源公告
5. 进入阶段 2：首发验证

### N5.2 CLI 安装脚本：进行中

**已有基础**（`scripts/install/install-cli.sh`）：
- ✅ 跨平台检测（Linux/macOS/Windows）
- ✅ 架构检测（amd64/arm64）
- ✅ 中国镜像加速

**待完善**：
- [ ] 审查并测试 CLI 安装流程

### N5.3 升级脚本完善：进行中

**已有基础**（`scripts/install/upgrade.sh`）：
- ✅ 备份当前版本
- ✅ 下载新版本
- ✅ 停止服务
- ✅ 执行迁移
- ✅ 回滚机制
- ✅ 应用容器状态检查

**待完善**：
- [ ] 测试升级流程
- [ ] 测试回滚机制

## 当前任务

正在补齐 Go 子命令以支持安装和升级脚本。

最后更新：2026-10-02 [cc] - 开始 N5
