# AcornFox 协作规则

Codex、Claude Code 共用本文件：Codex 直接读取，Claude Code 通过 `CLAUDE.md` 导入。规则只改这一处。

## 共享进度

| 文件 | 内容 |
| --- | --- |
| `docs/acornfox-rebuild-migration-plan.md` | v2 设计与 N0～N6 执行计划（权威） |
| `docs/current-milestone.md` | 当前里程碑的进度与验收清单 |
| `docs/active-tasks.md` | 任务认领情况与正在编辑的文件 |
| `docs/tech-decisions.md` | 技术决策记录 |
| `docs/evidence/` | 各阶段的验收证据 |

开始工作前先读 `current-milestone.md` 和 `active-tasks.md`。认领任务、开始改动、完成任务时更新 `active-tasks.md`；里程碑有实质进展时更新 `current-milestone.md`；重要技术决策写入 `tech-decisions.md`。

## 身份标识

提交信息和文档中用 `[codex]`、`[cc]`（Claude Code）标明作者。

## 避免冲突

- 开始一项任务时，在 `active-tasks.md` 的“正在编辑的文件”中登记要改的文件或目录，完成后删除登记。已被他人登记的文件不要同时修改。
- 几个编辑器共用同一个工作目录，修改前重新读取文件，不要基于旧内容覆盖。

## 代码约定

- Go 模块位于 `acornfox/`，所有 go 命令都在该目录执行。
- API 路由在 `internal/apiserver/apiserver.go` 注册，CLI 命令在 `internal/cli/`。
- 数据库结构只能通过在 `internal/state/migrations.go` 末尾追加新迁移来修改；已发布的迁移有校验和保护，不能改动。
- 修改 `Store`、`runner.API`、`client.API` 等接口时，同步补齐所有测试替身（`*_test.go` 中的 fake），并用 `go vet ./...` 确认测试能编译。
- 仅供测试使用的代码，文件名必须以 `_test.go` 结尾，否则会被编进正式程序。

## 验证

改动完成后在 `acornfox/` 执行：

    go build ./...
    go vet ./...
    go test ./...

在 macOS 上请用 `TMPDIR=/tmp go test ./...`，否则 `cmd/acornfox`、`internal/caddyroute` 会因 Unix socket 路径过长而失败（`bind: invalid argument`）。`internal/runner` 的 socket 测试依赖只在 Linux 上实现的对端凭据校验（`internal/peer`），在 macOS 上会报 `runner: unavailable`，以 Linux 开发机的结果为准。里程碑验收以开发机实测为准，证据写入 `docs/evidence/`。
