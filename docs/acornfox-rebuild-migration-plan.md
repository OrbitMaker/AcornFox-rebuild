# AcornFox 单机版：v2 设计与迁移清单

> 日期：2026-09-29。状态：负责人已确认 v2 设计方向（第 1～3 节）；N0 原型通过后再正式切换（第 5 节）。
> 上位文档：[AcornFox 战略与阶段路线图](acornfox-strategy-roadmap.md) 阶段 0～1。
> 代码位置：分支 `acornfox-rebuild-20260929`，目录 `acornfox/`。旧代码在分支 `archive/acornfox-thin-core-20260929`。
> 本文取代本文件此前的“保留核心能力、重建外壳”清单中尚未执行的部分（原 M3～M5）；已完成的 M0～M2 见第 8 节。

## 1. 设计原则

1. **状态记在 AcornFox，运行交给 Docker，访问交给 Caddy。** 能由 Docker、Caddy 做好的事不自己实现。
2. **调和而不是编排。** SQLite 记“应该是什么样”，Docker 标签反映“实际是什么样”，runner 让两者一致。重复执行安全，崩溃后重跑即可恢复，不记录“执行到哪一步”。
3. **只保留一道权限边界。** 对外处理请求的 server 不能访问 Docker；只有 runner 能访问，而且只接受有类型约束的请求。
4. **诊断是产品的一部分。** 每次失败都给出结构化结果，供用户工作台里的 AI 读取和修复。
5. **应用独立于 AcornFox。** 容器由 Docker 托管并设为自动重启，AcornFox 升级、崩溃、停止都不影响已运行的应用。

## 2. 结构

```text
用户电脑：acornfox CLI + Skill
      │ HTTPS + 访问令牌
      ▼
服务器
  Caddy ──── 控制台入口            → acornfox server（127.0.0.1）
        └─── 应用域名 / IP:端口     → 应用容器
  acornfox server  （账号 acornfox）      API、网页、认证、SQLite、调和、诊断
  acornfox runner  （账号 acornfox-exec，docker 组）  build / run / inspect / remove / logs / stats，无状态
  Docker Engine（自带 BuildKit；daemon.json 配国内镜像加速）
```

- `server`、`runner`、CLI 是同一个程序 `acornfox` 的三个子命令；服务器上两个 systemd 服务。
- server 与 runner 通过 `/run/acornfox/runner.sock` 通信，沿用已完成的 `internal/peer`（socket 0660、组 `acornfox-ipc`、按内核报告的对端 UID 校验）。只有 server 调 runner，runner 不回调 server。
- runner 使用 Docker 官方 Go SDK（Engine API），不调用 docker 命令行。
- 服务器依赖只有 Docker 和 Caddy。

## 3. 核心机制

### 3.1 状态模型（全新 SQLite 模式，迁移从 0001 开始）

| 表 | 内容 |
| --- | --- |
| 认证相关 | 管理员、会话、登录限速、访问令牌 |
| `apps` | 名称、容器端口、环境变量（密钥只存引用）、数据卷、域名 |
| `deployments` | 来源（上传包 / 镜像 / Git）、来源 digest、镜像 ID、期望状态、当前阶段、诊断 |
| `events` | 部署和操作事件，用于日志、审计和 CLI 进度查询 |

容器的实际情况只以 Docker 为准，不在 SQLite 中重复保存。受管容器、数据卷、网络都带 `acornfox.app` 与 `acornfox.deployment` 标签；没有标签的资源一律不碰。

### 3.2 调和器（server 内）

每个应用一个串行队列。触发条件：新部署、生命周期操作、server 启动、定时巡检。每轮：

1. 读 SQLite 中该应用的期望状态；
2. 通过 runner 读 Docker 中带该应用标签的实际资源；
3. 计算差异并调用 runner 做最少的动作（构建、创建、启动、停止、删除）；
4. 把结果和诊断写回 `deployments` 与 `events`。

所有 runner 动作按部署 ID 幂等：同一部署再执行一次，要么什么都不做，要么得到同样的结果。

### 3.3 部署流程

1. `acornfox deploy .`：CLI 按 `.dockerignore` 打包当前目录并上传，立即返回部署 ID；`acornfox status <id>` 查进度。现成镜像和公开 Git 是另外两种来源，后续流程相同。
2. runner 用 Docker 构建镜像。项目没有 Dockerfile 时由用户工作台的 AI 在本地生成，AcornFox 只做安全检查（沿用 `importers/dockerfile` 的规则）。
3. runner 启动新容器（带标签、资源上限、`unless-stopped` 重启策略、拒绝特权 / 宿主机挂载 / Docker socket / host 网络）。
4. 健康检查通过后，server 让 Caddy 把流量切到新容器，再让 runner 删除旧容器；失败时旧容器继续服务。
5. 返回网址，或返回诊断。

### 3.4 诊断格式（CLI、API、Skill 共用）

```json
{
  "stage": "upload | build | start | health | route",
  "code": "dockerfile_missing | build_failed | port_not_listening | registry_timeout | ...",
  "message": "给人看的一句话",
  "log_excerpt": "最多 40 行相关日志",
  "hint": "建议修改的位置或下一步"
}
```

错误码是稳定契约，新增不改名。

### 3.5 访问与 HTTPS

- 控制台与 API 经 Caddy 对外；server 本身只监听 127.0.0.1。CLI 用网页生成的访问令牌。
- 修复通道：Caddy 故障时用 `ssh -L` 连本机端口登录。这是文档说明的运维路径，不另做产品机制。
- 国内规则：
  - 中国大陆服务器上未备案的域名基本无法用 80/443 对外提供网站服务。默认给 `IP:高位端口`，可加 Caddy 自签 HTTPS；诊断和 Skill 负责说明原因。
  - 已备案域名：Caddy 自动申请正式证书。
  - 香港或海外服务器不受此限。

### 3.6 安装与升级

- `install.sh`：检查或安装 Docker、Caddy（优先使用国内可达的软件源），配置镜像加速，创建两个账号和组，安装程序文件和两个 systemd 服务，生成一次性初始化令牌。
- 升级：替换程序文件 → 执行 SQLite 迁移（迁移前自动备份）→ 重启两个服务；失败则恢复程序文件和数据库备份。应用容器全程不受影响。

### 3.7 明确不做

任务租约 / 代次 / outbox / 执行器回调、自写镜像仓库客户端和逐层校验、rootless BuildKit 与构建出站规则（及其 root 程序）、统一发行清单和分阶段安装器、进程 PID 证明、Compose（首发后再议）。

## 4. 现有代码的去留

| 现有 | 去向 |
| --- | --- |
| `internal/peer` | 保留，用于 server–runner socket |
| `internal/auth`、`corehttp` 中认证与初始化部分 | 保留，增加访问令牌 |
| `persistence/sqlite` 中存储打开、加锁、迁移执行、结构校验、认证表 | 保留写法；业务表按 3.1 新建 |
| `importers/dockerfile` | 保留安全检查规则 |
| `hostmetrics`、`dockermetrics`、`containermetrics` | 保留；容器指标改由 runner 提供数据 |
| `providers/volume`、`providers/standalone` 中容器参数与安全限制 | 参考重写到 runner |
| `providers/acornfoxroute` | 评估：若“只管自己那部分 Caddy 配置”的逻辑能直接复用则保留，否则重写为更小的路由模块 |
| `web/src/core`、`web/src/shared` | 保留，接口随新 API 调整 |
| `cmd/acornfox` | 保留命令框架；改为令牌认证、补 Windows、命令按新 API 重做 |
| `imageexecution`、`sourcebuildexecution`、`gatewayexecution`、`application`、`providers/{registryhttp,image,buildkit,source,capacity}`、`buildnetwork`、`cmd/acornfox-build-network`、`cmd/acornfox-executor`、`layout` | 由新 runner / 调和器取代；N1 完成后删除 |

## 5. 执行步骤

| 步骤 | 内容 | 完成标准 |
| --- | --- | --- |
| **N0 原型（1～2 天）** | 在开发机上用最少代码跑通：上传目录 → Docker 构建 → 运行 → Caddy 路由 → 网址；故意制造一次构建失败并返回诊断 | 实际浏览器访问成功；诊断包含阶段、错误码和日志片段；记录耗时与代码量。**通过后才进入 N1，否则回到本清单重新评估** |
| N1 状态与调和 | 新 SQLite 模式；runner（Docker SDK）；调和器；幂等与崩溃后恢复 | 部署中途杀掉 server 或 runner，重启后自动收敛到正确状态；重复提交同一部署不产生重复容器 |
| N2 部署入口 | API：上传包、现成镜像、公开 Git（GitHub + 一个国内平台）；CLI：`deploy`、`status`、`logs`、`diagnose`；访问令牌；Windows/macOS/Linux 编译 | 三个平台的 CLI 都能对开发机完成一次部署并拿到网址或诊断 |
| N3 访问 | Caddy 对外控制台与应用路由；IP:端口默认；已备案域名自动 HTTPS；未备案提示 | 远程浏览器与 CLI 经 HTTPS 访问控制台；应用可访问 |
| N4 生命周期与观测 | 停止、启动、重启、重新部署、删除（默认保留数据卷）；日志、主机与容器指标 | 操作后数据卷内容保留；网页与 CLI 显示状态、日志、指标 |
| N5 安装与升级 | `install.sh`、两个 systemd 服务、国内软件源与镜像加速、升级与回退 | 干净的国内云主机上一条命令安装；一次升级成功且应用不中断；故意让升级失败能回退 |
| N6 Skill 与验收 | Skill 与 `acornfox skill install`；路线图第 6.2 节首发验收 | 由未参与开发的人完成首发 7 项检查 |

与路线图的对应：阶段 0 退出 = N1～N3、N5 覆盖“干净安装 → 登录 → 部署现成镜像 → 浏览器访问”；阶段 1 退出 = N0～N6 全部完成。

## 6. 风险与应对

- **放弃构建出站控制：** 用户构建的是自己的代码，接受该风险；在文档中说明，后续如需可作为可选项加回。
- **放弃自写镜像校验：** 依赖 Docker 的内容寻址校验，只记录实际得到的镜像 digest。
- **Docker 访问等同 root：** 只有 runner 有权限，runner 只接受有类型的请求并拒绝危险容器参数；server 被攻破不直接获得 root。
- **重复推倒：** N0 设了明确的通过条件；N1 起不再接受架构层面的变更，新想法进入路线图待定池。

## 7. 待定

- Caddy、Docker 在国内的安装源（官方源、阿里云镜像站或安装包内置）。
- 如何判断服务器位于中国大陆（云厂商元数据、用户选择，或两者结合）。
- 公开 Git 首批支持的国内平台（Gitee 或 CNB）。

## 8. 已完成记录

- **M0**：存档分支 `archive/acornfox-thin-core-20260929`（提交 `577b5605`）；阿里云测试机 `i-REDACTED` 已销毁。
- **M1**（提交 `ef2ba9ba`）：新目录 `acornfox/`、模块 `github.com/acornfox/acornfox`，只迁入符合战略的代码；Go 产品代码 22.2 万行 → 6.8 万行。
- **M2**（提交 `65a87e2e`）：核心与执行器分离、`internal/peer` 按 UID 校验、删除功能包与 root 辅助进程、SQLite 迁移重排；Go 产品代码 → 5.1 万行。开发机上 `go test ./...` 29 个包通过。M2 的 `peer`、认证和存储写法是 v2 的起点，其余执行层由 N1 取代。
