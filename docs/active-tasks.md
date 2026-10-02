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

- 状态：⏳ `available`
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
