# AcornFox 单机版

让 AI 工作台里的一句“帮我部署”变成一个可访问的网址。本目录是单机版代码基线；旧代码保存在分支 `archive/acornfox-thin-core-20260929`。

## 当前状态

按 [v2 设计与迁移清单](../docs/acornfox-rebuild-migration-plan.md) 重建中：N0～N3 已通过开发机验收，N3 同时完成 Mac 原生 CLI、控制台和剪贴板检查（见 [N3 验收记录](../docs/evidence/n3-acceptance-2026-09-30.md)）。阶段 0 仍需 N5 的干净安装与升级；N4 完整运维观测、N6 Skill 与独立首发验收尚未完成。

## 运行时

```text
用户电脑：acornfox CLI + Skill ──SSH──┐
                                     ▼
acornfox server（账号 acornfox）  SQLite、调和器；可信 API 用 Unix socket，控制台仅监听回环地址
        │ Unix socket（internal/peer，按对端 UID 校验）
acornfox runner（账号 acornfox-exec，docker 组）  唯一操作 Docker 的程序，不保存状态
        │
      dockerd                 caddy（server 经 admin socket 只管理 af-* 路由）
```

- 状态记在 AcornFox（SQLite），运行交给 Docker，访问交给 Caddy。调和而不是编排：每轮对比期望与实际，只做必要动作；资源名固定（`af-<应用>-<部署ID>`），重复执行即幂等。
- server 或 runner 任一崩溃重启，已部署应用不受影响，未完成的部署自动接着做完。
- 只处理带 `acornfox.managed=1` 标签的 Docker 对象。

## 目录

```text
cmd/acornfox               经 SSH 的 CLI；服务器子命令 server、runner、proxy
internal/
  state                    SQLite 期望状态：应用、部署、环境变量、数据卷、附加服务、事件、管理员认证表
  runner                   Docker SDK 实现、peer socket 上的 HTTP 服务与客户端
  reconcile                调和器：推进部署、收敛、崩溃恢复、回收
  caddyroute               Caddy admin API 路由同步
  apiserver                Unix socket 可信 API；控制台会话、Host 检查与 CSRF
  console                  内嵌原生 JS/CSS 工作台
  cli client pack          跨平台命令、SSH 传输与目录打包
  peer                     Unix socket 边界（按对端 UID 校验）
  auth                     管理员密码与会话（N3 控制台登录复用）
  importers/dockerfile     Dockerfile 安全检查规则（待接入）
  hostmetrics containermetrics dockermetrics   主机与容器指标（N4 接入）
  contracts domain foundation application/contracts compatibility   旧 CLI 与指标仍依赖的类型，N2 后按需精简
```

## 构建与测试

在 Linux 上构建与测试（`internal/runner` 的部分测试依赖 Linux）：

```bash
GOTOOLCHAIN=go1.25.13 go build ./...
GOTOOLCHAIN=go1.25.13 go test -race ./...
ACORNFOX_DOCKER_IT=1 go test -race -run Docker ./internal/runner/   # 需要本机 Docker
```

## 已知问题

- 停止应用最多延迟一轮巡检（约 10 秒）才生效，N4 改为立即执行。
- 正式安装时 server 与 runner 分属两个账号，上传目录需对 `acornfox-ipc` 组可读（N5）。
- `internal/containermetrics` 的定时测试在机器繁忙时偶发失败，需要改为不依赖真实时间。
