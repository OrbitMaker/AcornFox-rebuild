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

- 状态：🔜 `available`
- 负责：待认领
- 内容：完善并测试 `scripts/install/install.sh`
  - 替换二进制下载 TODO
  - 实机测试（国内云主机）
- 相关文件：`scripts/install/install.sh`

## N5.3 升级脚本测试

- 状态：🔜 `available`
- 负责：待认领
- 内容：测试升级和回滚机制
  - 正常升级流程
  - 迁移失败回滚
  - 服务启动失败回滚
- 相关文件：`scripts/install/upgrade.sh`

## N5.4 CLI 安装脚本审查

- 状态：🔜 `available`
- 负责：待认领
- 内容：审查和测试客户端安装脚本
- 相关文件：`scripts/install/install-cli.sh`

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
