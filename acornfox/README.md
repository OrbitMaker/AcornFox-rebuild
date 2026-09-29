# AcornFox 单机版

让 AI 工作台里的一句“帮我部署”变成一个可访问的网址。本目录是单机版代码基线，只保留符合[战略与阶段路线图](../docs/acornfox-strategy-roadmap.md)的代码；旧代码保存在分支 `archive/acornfox-thin-core-20260929`。

## 当前状态

按 [v2 设计与迁移清单](../docs/acornfox-rebuild-migration-plan.md) 重建中：N0 原型、N1 状态与调和已完成并在开发机验收（记录见迁移清单第 8 节，实现契约见 [n1-contract.md](../docs/n1-contract.md)）。下一步 N2：CLI 经 SSH 部署。

## 运行时

```text
用户电脑：acornfox CLI + Skill ──SSH──┐
                                     ▼
acornfox server（账号 acornfox）  API、SQLite 期望状态、调和器；只监听 127.0.0.1
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
cmd/acornfox               CLI；子命令 server、runner（旧 CLI 命令在 N2 按新 API 重做）
internal/
  state                    SQLite 期望状态：应用、部署、环境变量、数据卷、附加服务、事件、管理员认证表
  runner                   Docker SDK 实现、peer socket 上的 HTTP 服务与客户端
  reconcile                调和器：推进部署、收敛、崩溃恢复、回收
  caddyroute               Caddy admin API 路由同步
  apiserver                server 的 HTTP API（N1 无认证，只允许回环地址）
  peer                     Unix socket 边界（按对端 UID 校验）
  auth                     管理员密码与会话（N3 控制台登录复用）
  importers/dockerfile     Dockerfile 安全检查规则（待接入）
  hostmetrics containermetrics dockermetrics   主机与容器指标（N4 接入）
  contracts domain foundation application/contracts compatibility   旧 CLI 与指标仍依赖的类型，N2 后按需精简
prototype/                 N0 原型与控制台设计稿（只作参考）
web/                       旧网页控制台；N3 按工作台设计重做
```

## 构建与测试

项目约定不在开发者 Mac 上执行 Go 构建，统一在开发机（`yanyan-devbox`）上进行：

```bash
GOTOOLCHAIN=go1.25.13 go build ./...
GOTOOLCHAIN=go1.25.13 go test -race ./...
ACORNFOX_DOCKER_IT=1 go test -race -run Docker ./internal/runner/   # 需要本机 Docker
```

## 已知问题

- 停止应用最多延迟一轮巡检（约 10 秒）才生效，N4 改为立即执行。
- 内存超限的提示引用的 `acornfox app set --memory` 在 N2 才提供。
- 正式安装时 server 与 runner 分属两个账号，上传目录需对 `acornfox-ipc` 组可读（N5）。
- `internal/containermetrics` 的定时测试在机器繁忙时偶发失败，需要改为不依赖真实时间。
- `web/` 仍对接旧 API，N3 重做前不可用。
