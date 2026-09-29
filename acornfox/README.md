# AcornFox 单机版

让 AI 工作台里的一句“帮我部署”变成一个可访问的网址。本目录是单机版代码基线，只保留符合[战略与阶段路线图](../docs/acornfox-strategy-roadmap.md)的代码；旧代码保存在分支 `archive/acornfox-thin-core-20260929`。

## 当前状态

迁移清单 M2 已完成（见[迁移清单](../docs/acornfox-rebuild-migration-plan.md)第 7 节）：运行时已收敛为核心加执行器。尚未提供安装方式（M3），因此还没有在真实主机上跑通核心与执行器的端到端流程。

## 运行时

```text
                 浏览器 / CLI
                      │ HTTP（目前只监听 127.0.0.1）
        ┌─────────────▼─────────────┐
        │ acornfox-core（账号 acornfox）│  API、网页、认证、SQLite、任务调度
        └─────────────┬─────────────┘  不能访问 Docker / BuildKit / Caddy
     Unix socket（/run/acornfox，组 acornfox-ipc，双方只接受对方 UID）
        ┌─────────────▼─────────────┐
        │ acornfox-executor（账号 acornfox-exec）│  容器运行、源码构建、网关
        └──┬───────────┬───────────┬┘  只接受核心发来的有类型请求
           │           │           │
        dockerd   buildkitd       caddy
                 （rootless）
        acornfox-build-network（root）  构建期出站网络规则（nftables）
```

- 执行器里容器运行是必需的；源码构建、网关在依赖（BuildKit、Caddy）就绪时启动，否则定期重试，不影响已部署应用的管理。
- 核心按执行器健康状态启停对应的任务消费者；执行器不在时，登录、查看等功能照常可用，任务在执行器恢复后继续。
- 账号、目录和 socket 路径定义在 `internal/layout`。

## 目录

```text
cmd/
  acornfox                 CLI
  acornfox-core            核心服务
  acornfox-executor        执行器
  acornfox-build-network   构建网络规则（root）
internal/
  layout                   主机路径与账号
  peer                     核心与执行器之间的 Unix socket（按对端 UID 校验）
  persistence/sqlite       本机唯一权威数据（迁移 0001～0009）
  application              镜像部署 / 生命周期 / 源码构建 / 域名 的业务服务与契约
  corehttp  auth           HTTP 接口、管理员认证与会话
  imageexecution           拉取 → 校验 digest → 创建并启动容器 → 读回端口 → 观测
  sourcebuildexecution     固定 Git 提交 → 受限 BuildKit 构建 → 导出 OCI 镜像
  gatewayexecution         为已部署应用写入 Caddy 路由并观测证书
  providers/               registryhttp、image、buildkit、source、acornfoxroute、volume、standalone、capacity
  importers/dockerfile     Dockerfile 静态解析与安全拒绝
  hostmetrics containermetrics dockermetrics   主机与容器指标、近期趋势
  buildnetwork             构建期出站网络控制
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

- 核心只监听回环地址，远程的浏览器和 CLI 目前无法访问。首发需要一个带 HTTPS 的对外入口（M3/M4 决定方案）。
- CLI 仍为 Cookie + CSRF 会话，Windows 下无法编译（缺少读密码实现），M4 处理。
- `go vet` 有 2 条既有警告：`internal/providers/capacity` 一处不可达代码；一个测试里的自赋值。
- `internal/containermetrics` 的定时测试偶发失败，需要改为不依赖真实时间。
- 网页类型 `web/src/api/acornfox-generated-schema.ts` 由旧 OpenAPI 生成，M4 改为从核心 OpenAPI 生成。
