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

里程碑：N6。待开始。

## N6.1 Skill 开发

- 状态：🔜 `available`
- 负责：待认领
- 内容：开发 AcornFox Skill 用于 AI 工作台集成
  - `acornfox skill install` 命令
  - Skill 定义文件
  - 与 dbskill、Claude Code 等工作台集成
- 相关代码：待创建

## N6.2 首发验收

- 状态：🔜 `available`
- 负责：待认领
- 内容：按路线图第 6.2 节完成 7 项首发检查
  - 由未参与开发的人完成验收
  - 文档完整性检查
  - 用户体验验证
- 相关文档：`docs/acornfox-strategy-roadmap.md` 第 6.2 节

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

最后更新：2026-10-02 [cc] - 开始 N5
