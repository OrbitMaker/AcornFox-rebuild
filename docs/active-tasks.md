# 活跃任务

里程碑：N5。状态取值：`available` 可认领、`in_progress` 进行中、`review` 待实测、`completed` 已完成、`blocked` 被阻塞。各任务的已完成内容见 `current-milestone.md`。

以下代码路径都在 `acornfox/` 下。

## N5.1 子命令补齐

- 状态：✅ `completed` (2026-10-02)
- 负责：[cc] 主会话
- 已完成：
  - ✅ `acornfox version` - 输出版本信息
  - ✅ `acornfox init` - 初始化数据库
  - ✅ `acornfox migrate` - 执行数据库迁移
  - ✅ `acornfox admin-token` - 生成初始管理员令牌
  - ✅ 编译和测试验证通过
- 相关代码：`cmd/acornfox/install_commands.go` (新增)、`cmd/acornfox/main.go` (更新)

## N5.2 安装脚本完善

- 状态：✅ `completed` (2026-10-02)
- 负责：[cc] 主会话
- 已完成：
  - ✅ Caddy 安装改进（国际环境使用 apt 仓库）
  - ✅ 实现自动 latest 版本检测
  - ✅ GitHub 镜像加速
  - ✅ 错误处理和版本验证
- 相关代码：`scripts/install/install.sh`

## N5.3 升级脚本完善

- 状态：✅ `completed` (2026-10-02)
- 负责：[cc] 主会话
- 已完成：
  - ✅ 添加自动 latest 版本检测
  - ✅ 镜像加速逻辑一致性
  - ✅ 完整的备份和回滚机制
- 相关代码：`scripts/install/upgrade.sh`

## N5.4 CLI 安装脚本审查

- 状态：✅ `completed` (2026-10-02)
- 负责：[cc] 主会话
- 已完成：
  - ✅ 添加自动 latest 版本检测
  - ✅ 支持指定版本参数
  - ✅ 跨平台兼容性验证
  - ✅ 中国镜像加速
- 相关代码：`scripts/install/install-cli.sh`

---

# N6 Skill 与验收

里程碑：N6。进行中（2026-10-02）。

## N6.1 Skill 开发

- 状态：✅ `completed` (2026-10-02)
- 负责：[cc] 主会话
- 已完成：
  - ✅ `acornfox skill install` 命令实现
  - ✅ 自动检测 5 个工作台（Claude Code, Cursor, Windsurf, 豆包, 通义灵码）
  - ✅ 跨平台支持（Windows/macOS/Linux）
  - ✅ Skill 内容完整
  - ✅ 实际测试通过
- 相关代码：`internal/cli/skill.go`

## N6.2 首发验收

- 状态：✅ `completed`（2026-10-10 负责人确认）
- 原状态：⏳ `available`（2026-10-09 [cc] 已完成开发者自测，见 `evidence/n6-clean-host-2026-10-09.md`）
- 负责：待认领（需未参与开发的人）
- 内容：按验收清单完成 7 项检查
  - 在干净 Ubuntu 24.04 服务器上
  - 至少 3 个工作台通过完整流程
  - 记录验收结果
- 相关文档：`docs/n6-acceptance-checklist.md`

---

## 正在编辑的文件

- `docs/current-milestone.md` - [cc] 2026-10-02
- `docs/active-tasks.md` - [cc] 2026-10-02
- `docs/n6-acceptance-checklist.md` - [cc] 2026-10-02（新增）

## 认领流程

1. 选一个 `available` 的任务，改为 `in_progress` 并写上自己的标识。
2. 在下方“正在编辑的文件”中登记要改的文件或目录。
3. 完成后按 `AGENTS.md` 的验证命令检查，更新任务状态，删除登记。

## 正在编辑的文件

| 文件或目录 | 编辑者 | 开始时间 | 说明 |
| --- | --- | --- | --- |
| `cmd/acornfox/` | [cc] 主会话 | 2026-10-02 | 补齐 version/init/migrate/admin-token 子命令 |
| `internal/cli/` | [cc] 主会话 | 2026-10-02 | 版本常量和子命令实现 |
| `docs/current-milestone.md` | [cc] 主会话 | 2026-10-02 | N5 进度跟踪 |
| `scripts/install/install.sh` | [cc] 主会话 | 2026-10-02 | 首发前修复：上传目录与 /run/acornfox 权限、tmpfiles、Caddy socket |
| `acornfox/internal/apiserver/deployments.go` | [cc] 主会话 | 2026-10-02 | 恢复 defer Close，修正 7628b6f1 的多余改动 |
| `scripts/install/upgrade.sh` | [cc] 主会话 | 2026-10-02 | 修正数据库路径、先停服务再备份、非交互参数、补齐目录布局 |
| `acornfox/internal/caddyroute/` | [cc] 主会话 | 2026-10-02 | 无 http app 时 Caddy 返回 400 traversal，路由同步无法初始化 |
| `acornfox/internal/cli/`（skill、diagnose、Version） | [cc] 主会话 | 2026-10-02 | Skill 改为 SKILL.md 目录格式；补 diagnose；统一版本号 |
| `acornfox/cmd/acornfox/` | [cc] 主会话 | 2026-10-02 | version 移出 !windows 文件，修 Windows 构建 |
| `scripts/install/install-cli.sh`、`scripts/build-release.sh`、`skills/` | [cc] 主会话 | 2026-10-02 | 去掉已停服的 ghproxy.com；发布产物构建脚本 |

最后更新：2026-10-02 [cc] - 首发前修复

## 张家口测试机公网控制台接入

- 状态：✅ `completed`（2026-10-04）
- 负责：[codex] 主会话；按用户最新要求停止 Claude Code，主代理接管实现、部署及验收。
- 范围：`panel.acornfox.com` 公网 HTTPS、管理员认证、原生控制台会话桥接；保留可信 API Unix socket 与 CSRF 校验。
- 修改：新增 `acornfox/cmd/acornfox-public-console/`、`scripts/ops/public-console/`；新增实机证据与 ADR-0009。
- 验证：目标命令 build/vet；真实公网证书、401 认证拦截、控制台/应用列表/主机指标 200、CSRF 与 Origin 拦截、Caddy reload 持久入口；网关启用开机启动。
- 证据：[公网控制台验收](evidence/public-console-2026-10-04.md)。历史测试应用部署失败状态保留；本任务不改变 N6 独立用户首发验收状态。
- 本轮文件编辑已结束，没有遗留写入认领；上方其他任务记录保留。

---

# N7 首发收尾（品牌与界面）

里程碑：N7。进行中（2026-10-10）。清单见 `current-milestone.md`。

## N7.1 控制台重做

- 状态：`completed`（2026-10-11 [cc] 代码与构建测试已完成，见 `evidence/console-redesign-2026-10-10.md`；实机查看、截图与 Linux 全量测试按负责人决定并入 N7.3 的测试机实机检查，即 `current-milestone.md` 第 4 项）
- 负责：[cc]
- 相关代码：`acornfox/internal/console/static/`

## N7.2 官网重做

- 状态：`completed`（2026-10-11 [cc] 代码已完成，静态验证通过，见 `evidence/website-redesign-2026-10-11.md`；待负责人确认文案后提交，部署与实机查看属于 N7.3）。2026-10-11 [cc] 已落实负责人对 5 个确认项的决定，见证据第 6 节；控制台公网访问选项见 ADR-0016（已接受并实现，即 N7.4）；标志文字已改为 AcornFox
- 负责：[cc]
- 相关代码：`website/`

## N7.3 发版与官网部署

- 状态：`available`
- 内容：测试机实机检查 → 发版并同步 Gitee → 部署官网
- 官网部署后的实机查看（截图要求见 `current-milestone.md` 第 6 项）与测试机控制台检查（第 4 项）分开进行（2026-10-11 [cc]）
- 测试机实机检查另含 N7.1 转来的两项（2026-10-11 [cc]）：控制台截图（桌面与手机、深浅色，并查看浏览器控制台报错与布局），以及在 Linux 上跑 `go test ./...` 并全量通过（含 `internal/runner`）
- 测试机实机检查还包括第 12 项公网访问控制台的真实开通：已备案域名、未备案域名、未放行端口三种情形，细节见 `current-milestone.md` 第 4 项第 ③ 条（2026-10-11 [cc]）

## N7.4 控制台公网访问（里程碑第 12 项，ADR-0016）

- 状态：`completed`（2026-10-11 [cc] 代码与单元测试已完成，见 `evidence/public-console-option-2026-10-11.md`；真实环境验证属于 N7.3 的测试机实机检查）。2026-10-11 负责人确认 ADR-0016 的三个待定事项，见 ADR“已决定”一节
- 待办：测试机 `panel.acornfox.com` 迁移到本功能（先停旧网关，需负责人另行批准）；迁移后删除 `acornfox/cmd/acornfox-public-console/`、`scripts/ops/public-console/`
- 负责：[cc]
- 相关代码：`acornfox/internal/publicconsole/`、`internal/caddyroute/verify.go`、`internal/cli/public_console.go`、`internal/apiserver/public_console.go`、`scripts/install/install.sh`、`skills/acornfox/SKILL.md`

## 正在编辑的文件（N7）

| 文件或目录 | 编辑者 | 开始时间 | 说明 |
| --- | --- | --- | --- |