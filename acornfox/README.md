# AcornFox 单机版

让 AI 工作台里的一句“帮我部署”变成一个可访问的网址。本目录是 2026-09-29 整理后的单机版代码基线，只保留符合[战略与阶段路线图](../docs/acornfox-strategy-roadmap.md)的代码；旧代码保存在分支 `archive/acornfox-thin-core-20260929`。

## 当前状态

迁移清单 M1 已完成：保留的核心已迁入，Linux 下 `go build`、`go vet`、`go test ./...`（36 个包）通过，网页 `npm run build` 与 `npm test` 通过。运行时仍是迁移前的多进程结构，M2 起收敛为一个核心进程加一个 root 辅助进程。尚未提供安装方式（M3）。详见[迁移清单](../docs/acornfox-rebuild-migration-plan.md)。

## 结构

```text
cmd/
  acornfox                 CLI：登录、镜像部署与生命周期、源码构建、域名、主机指标
  acornfox-core            核心服务：HTTP API、网页、认证、SQLite、任务调度
  acornfox-container       容器执行（M2 并入核心）
  acornfox-source-build    源码构建执行（M2 并入核心）
  acornfox-gateway         网关执行（M2 并入核心）
  acornfox-build-network   构建网络隔离
  acornfox-host-helper     root 辅助进程
internal/
  persistence/sqlite       本机唯一权威数据：应用、部署、任务、审计、outbox、幂等
  application              镜像部署 / 生命周期 / 源码构建 / 域名 的业务服务与契约
  corehttp  auth           HTTP 接口、管理员认证与会话
  imageexecution           拉取 → 校验 digest → 创建并启动容器 → 读回端口 → 观测
  sourcebuildexecution     固定 Git 提交 → 受限 BuildKit 构建 → 导出 OCI 镜像
  gatewayexecution         为已部署应用写入 Caddy 路由并观测证书
  providers/               registryhttp、image、buildkit、source、acornfoxroute、volume、standalone、capacity
  importers/dockerfile     Dockerfile 静态解析与安全拒绝
  hostmetrics containermetrics dockermetrics   主机与容器指标、近期趋势
  buildnetwork             构建期出站网络控制
  hosthelper localpeer packmanager packprotocol corelaunch   多进程通信与身份校验（M2 移除）
web/                       网页控制台（React）
```

## 构建与测试

项目约定不在开发者 Mac 上执行 Go 构建，统一在开发机（`yanyan-devbox`）上进行：

```bash
GOTOOLCHAIN=go1.25.13 go build ./...
GOTOOLCHAIN=go1.25.13 go test ./...
cd web && npm ci && npm run build && npm test
```

## 已知问题

- `go vet` 有 4 条既有警告：`cmd/acornfox-core/main.go` 的 `cancelSource` 可能泄漏上下文；`internal/providers/capacity` 一处不可达代码；一个测试里的自赋值。
- `internal/containermetrics` 的定时测试偶发失败（约三分之一），与迁移无关，需要改为不依赖真实时间。
- CLI 仍为 Cookie + CSRF 会话，Windows 下无法编译（缺少读密码实现），M4 处理。
- 网页类型 `web/src/api/acornfox-generated-schema.ts` 由旧 OpenAPI 生成，M4 改为从核心 OpenAPI 生成。
