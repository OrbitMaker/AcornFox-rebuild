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
      │ SSH（默认；管理接口不对公网开放）
      ▼
服务器
  acornfox server（只监听 127.0.0.1）  ← CLI 经 SSH 访问；`acornfox open` 经 SSH 隧道打开网页控制台
  Caddy ──── 应用域名 / IP:端口     → 应用容器
        └─── 控制台（可选：绑定已备案域名后才对外开放 HTTPS）
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
| 认证相关 | 管理员、会话、登录限速（访问令牌推迟到公网控制台路径） |
| `apps` | 名称（同一服务器唯一）、容器端口、健康检查路径、域名、期望状态（运行 / 停止） |
| `app_env` | 环境变量；标记为密钥的只写不读（见第 3.10 节） |
| `app_volumes` | 需要保存的容器内目录及对应的服务器目录 |
| `addons` | 附加服务（类型、固定版本、数据目录、生成的凭据、注入的变量名） |
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

### 3.5 访问方式（2026-09-29 确认选项 4：默认 SSH，已备案域名可选 HTTPS）

- **默认只走 SSH。** server 只监听 127.0.0.1，管理接口和登录页不对公网开放。CLI 通过用户已有的 SSH 登录方式连到服务器，在 SSH 通道里调用 server；AI 工作台执行 CLI 时无需复制令牌。
- **网页控制台：** `acornfox open` 自动建立 SSH 隧道并打开浏览器。
- **目标配置：** `acornfox target add my-server --ssh user@host`，自动读取用户现有的 SSH 配置；连不上时返回结构化诊断（主机不可达、认证失败、未安装 AcornFox 等）。
- **可选公网控制台（首发后）：** 绑定已备案域名后，可由 Caddy 以正式证书对外开放控制台；此时才需要访问令牌和登录限速。
- **应用访问（不变）：** 中国大陆服务器上未备案域名基本无法用 80/443 对外服务，默认给 `IP:高位端口`；已备案域名由 Caddy 自动申请证书；香港或海外服务器不受此限。诊断和 Skill 负责说明原因。

### 3.6 安装与升级

- `install.sh`：检查或安装 Docker、Caddy（优先使用国内可达的软件源），配置镜像加速，创建两个账号和组，安装程序文件和两个 systemd 服务，生成一次性初始化令牌。
- 升级：替换程序文件 → 执行 SQLite 迁移（迁移前自动备份）→ 重启两个服务；失败则恢复程序文件和数据库备份。应用容器全程不受影响。

### 3.7 明确不做

任务租约 / 代次 / outbox / 执行器回调、自写镜像仓库客户端和逐层校验、rootless BuildKit 与构建出站规则（及其 root 程序）、统一发行清单和分阶段安装器、进程 PID 证明、Compose（首发后再议）。

### 3.8 控制台界面规范

以设计稿 `acornfox/prototype/ui-workbench/index.html` 的“推荐”方案为准：工作台形式，桌面只放用户的应用图标（带状态点），底部 Dock 放工具（部署、服务器、日志、让 AI 部署、设置），应用详情以窗口打开；有应用失败时图标上方出现“需要处理”提醒条（最多 3 条，每条可“查看”“复制给 AI”），没有问题时不显示；图标下方一行灰字显示运行数与主机资源。规则：桌面只放应用；问题主动浮现、无问题不打扰；每个问题可一键交给 AI；细节放窗口里。待补：图标体系、多应用排列与 ⌘K、部署中 / 已停止 / 执行器断开等状态、危险操作确认、浅色与移动端、无障碍、用词表。

### 3.9 附加服务（2026-09-29 确认）

应用需要数据库时，在同一台服务器上以容器提供，不做托管数据库：

- `acornfox add postgres|mysql|redis --app NAME`：在该应用的专用 Docker 网络中启动数据库容器，使用固定版本的官方镜像，自动生成凭据（存为密钥引用、不回显），并把连接地址作为环境变量（如 `DATABASE_URL`、`REDIS_URL`）注入应用，随后重新部署应用。
- 数据库端口只在应用网络内可见，不对外发布；数据卷默认保留，删除应用或附加服务时须明确选择是否删除数据。
- 附加服务是 `apps` 下的一类资源，由同一个调和器管理（N1 表结构中体现），不引入 Compose。
- 不含备份、主从与升级迁移；这些是云版托管数据库的范围。首发只保证“能用、数据不丢于重新部署”。
- 诊断：应用缺少数据库连接变量时，提示可用 `acornfox add` 补上。

### 3.10 N1 数据约定（2026-09-29 确认）

1. **首发只支持网页 / API 应用**：对外提供 HTTP、能通过健康检查的应用。后台任务、定时任务放到首发之后。
2. **应用身份**：应用名在同一台服务器上唯一。CLI 首次部署后在项目目录写入 `.acornfox`（服务器名 + 应用名，不含任何密钥），再次部署时自动读取，避免重复建应用。
3. **应用数据保存**：容器里写的文件会随重新部署丢失，所以把需要保存的目录挂为 Docker 命名数据卷（`af-<应用>-<序号>`，首次挂载自动继承镜像中该目录的文件与权限，避免宿主目录属主不符导致写入失败）。来源：自动识别 Dockerfile 的 `VOLUME`；用 `acornfox volume add <容器内路径>` 补充（下次部署生效）；部署后检查容器内新写出的 `.db` / `.sqlite` 等文件，不在保存目录中时给出诊断 `data/unpersisted_database` 并提示命令。删除应用时数据目录默认保留。只保证重新部署不丢，服务器损坏仍会丢，首发不提供备份，文档写明。
4. **密钥**：存在 SQLite 中，数据库文件仅 `acornfox` 账号可读（0600）；接口只写不读，界面和 CLI 只显示“已设置”；日志和诊断中出现的密钥值做替换。不做同机加密（密钥只能放在同一台机器上，意义不大）。
5. **版本保留与回退**：每个应用保留最近 3 个成功版本的镜像，支持 `acornfox rollback`（即以上一版镜像新建一次部署）；更早的镜像和失败构建的镜像自动清理。
6. **N1 审核补充（2026-09-29）**：每应用默认资源上限 512 MB 内存、1 CPU（可调）；全机同时只构建 1 个；环境变量对服务器管理员（root / docker 组）可见，AcornFox 只保证 API、界面、CLI 与日志不显示密钥；N1 含最基础的 Caddy 切换（IP:端口），域名与 HTTPS 仍在 N3；上传包先落盘到 `/var/lib/acornfox/uploads/<部署ID>.tar`，部署结束后删除，用于崩溃后重建。

## 4. 现有代码的去留（N1 后已执行）

- **已删除**（2026-09-29，可从 git 历史找回）：`cmd/acornfox-core`、`cmd/acornfox-executor`、`cmd/acornfox-build-network`、`internal/{imageexecution,sourcebuildexecution,gatewayexecution,buildnetwork,layout,corehttp,persistence,providers,acornfoxrelease,observability}`、`internal/application` 的业务服务、`release/`。Go 代码约 9.1 万行 → 3.6 万行（含测试）。其中 `corehttp` 与 `persistence/sqlite` 原计划部分保留，但它们依赖已删除的执行层：认证表已复制进 `internal/state`，登录接口在 N3 基于 `internal/auth` 重写。
- **保留**：`peer`、`auth`、`importers/dockerfile`（安全规则，待接入）、三个指标包（N4 接入）、`web/`（N3 重做）、`cmd/acornfox`（N2 改为经 SSH 并按新 API 重做命令）；旧 CLI 与指标仍依赖的 `contracts`、`domain`、`foundation`、`application/contracts`、`compatibility` 在 N2 后按需精简。

## 5. 执行步骤

| 步骤 | 内容 | 完成标准 |
| --- | --- | --- |
| **N0 原型（1～2 天）** | 在开发机上用最少代码跑通：上传目录 → Docker 构建 → 运行 → Caddy 路由 → 网址；故意制造一次构建失败并返回诊断 | 实际浏览器访问成功；诊断包含阶段、错误码和日志片段；记录耗时与代码量。**通过后才进入 N1，否则回到本清单重新评估** |
| N1 状态与调和 | 新 SQLite 模式（含附加服务）；runner（Docker SDK）；调和器；幂等与崩溃后恢复 | 部署中途杀掉 server 或 runner，重启后自动收敛到正确状态；重复提交同一部署不产生重复容器 |
| N2 部署入口 | API：上传包、现成镜像、公开 Git（任意 HTTPS 地址，可指定分支或提交；首发实测 GitHub、Gitee、CNB；克隆超时给出 `source/clone_timeout` 诊断）；CLI：`target add --ssh`、`deploy`、`status`、`logs`、`diagnose`、`env set`，经 SSH 访问 server；Windows/macOS/Linux 编译 | 三个平台的 CLI 都能对开发机完成一次部署并拿到网址或诊断 |
| N3 访问 | `acornfox open`（SSH 隧道打开控制台）；Caddy 应用路由；IP:端口默认；已备案域名自动 HTTPS；未备案提示；控制台界面按第 3.8 节 | 从用户电脑一条命令打开控制台；应用可访问；控制台对公网不可见 |
| N4 生命周期与观测 | 停止、启动、重启、重新部署、删除（默认保留数据卷）；附加服务 `add` / 删除；日志、主机与容器指标 | 操作后数据卷内容保留；网页与 CLI 显示状态、日志、指标 |
| N5 安装与升级 | `install.sh`、两个 systemd 服务、国内软件源与镜像加速、升级与回退 | 干净的国内云主机上一条命令安装；一次升级成功且应用不中断；故意让升级失败能回退 |
| N6 Skill 与验收 | Skill 与 `acornfox skill install`；路线图第 6.2 节首发验收 | 由未参与开发的人完成首发 7 项检查 |

与路线图的对应：阶段 0 退出 = N1～N3、N5 覆盖“干净安装 → 登录 → 部署现成镜像 → 浏览器访问”；阶段 1 退出 = N0～N6 全部完成。

## 6. 风险与应对

- **放弃构建出站控制：** 用户构建的是自己的代码，接受该风险；在文档中说明，后续如需可作为可选项加回。
- **放弃自写镜像校验：** 依赖 Docker 的内容寻址校验，只记录实际得到的镜像 digest。
- **Docker 访问等同 root：** 只有 runner 有权限，runner 只接受有类型的请求并拒绝危险容器参数；server 被攻破不直接获得 root。
- **重复推倒：** N0 设了明确的通过条件；N1 起不再接受架构层面的变更，新想法进入路线图待定池。

## 7. 待定

- **附加服务：** 已确认，见第 3.9 节。
- **N1～N3 需补的产品细节：** 项目与应用对应（`.acornfox` 文件）、数据目录声明、`env set` 与密钥不回显、健康检查可配置、旧镜像清理、日志保留、镜像加速默认值（评估 DaoCloud 公共地址）、“复制给 AI”的说明前缀。

- Caddy、Docker 在国内的安装源（官方源、阿里云镜像站或安装包内置）。
- 如何判断服务器位于中国大陆（云厂商元数据、用户选择，或两者结合）。

## 8. 已完成记录

- **N3**（2026-09-30，开发机 + Mac 验收通过；[完整证据](evidence/n3-acceptance-2026-09-30.md)）：Mac `acornfox open` 经 SSH 打开控制台、单次登录和地址栏脱敏；真实检查 401、Host 421、CSRF 403、会话注销；三应用／两故障提醒、诊断复制、密钥隐藏、启停和回退通过；轮询保留键盘焦点、确认框焦点、日志滚动和诊断展开；内部 CA HTTPS、HTTP 308、证书验证失败诊断与恢复、解绑清理通过；20 个测试包 race 和六平台编译通过。修复了窗口遮罩盖住按钮、HTTP host 路由抢先返回内容、TLS 策略重复 ID、轮询重绘丢失交互状态及误报复制／操作完成。开发机已信任内部 CA，负向测试使用另一份测试 CA，不修改宿主信任。仅为 N3 开发机验收，N5 干净安装／升级、真实公网 ACME、Windows 实机和 N6 首发仍待。

- **N0**（提交 `856bdbbf`，2026-09-29 通过）：开发机上从 Linux 与 macOS CLI 各完成一次“上传目录 → Docker 构建 → 运行 → Caddy 路由 → 网址”（约 3～4 秒）；重新部署期间 25 次探测全部 200；构建失败、启动崩溃、缺少 Dockerfile 均返回结构化诊断。发现并修正：自动重启会把崩溃误判为端口无响应（改为检查期间有重启即判定退出）；构建日志需去掉颜色码和步骤噪音。确认 Docker 29 可通过 API 使用传统构建器。结论：v2 方向成立，进入 N1。原型代码只作参考，不直接进入正式实现。
- **N1**（提交 `3cd22119`、`84e8f390`、`ea5e889e`，2026-09-29 通过）：`internal/state`、`runner`、`reconcile`、`caddyroute`、`apiserver` 与 `acornfox server` / `runner` 子命令。开发机实测：部署约 4 秒；重新部署期间 223 与 368 次探测全部 200；在排队、构建、健康检查、切换流量各时间点 `kill -9` server 或 runner，重启后都自动上线且无残留；同键与同内容重复提交只产生 1 个部署，连续 3 次提交只构建最后一个；`VOLUME /data` 自动保存，十余次重新部署、强杀与回退后数据不丢；写入容器内的 SQLite 触发 `data/unpersisted_database`；512 MB / 1 CPU / 日志轮转生效，超内存报 `health/out_of_memory`；无标签的同名前缀容器全程未被触碰，带标签的孤儿容器被清理；镜像按“当前 + 3 个旧版”回收。实测发现并修正 7 个问题：runner 构建目录错指 `/tmp`；每 30 秒只推进一个阶段（82 秒 → 4 秒）；Caddy 更新误用 PUT（只能新建）且失败原因未记录；runner 短暂断开被计为构建中断；未关 swap 导致内存上限无效；端口提示给出宿主端口。遗留：停止最多延迟一轮巡检（N4）、`acornfox app set` 命令（N2）、两账号下上传目录权限（N5）。
- **N2**（提交 `96106a61`、`cf69044c`、`f1586cee`，2026-09-29 通过；契约 `docs/n2-contract.md`）：CLI 调用系统 `ssh` 执行服务器上的 `acornfox proxy`，一条命令只建一次 SSH；server 改为监听 Unix socket（组 `acornfox-users`）。实测：Mac 上 `target add devbox --ssh yanyan-devbox` 后在项目目录 `acornfox deploy` 约 4 秒拿到网址并写入 `.acornfox`，之后不带参数即可重新部署；`--json` 在成功、构建失败、连接失败时都输出统一形状；现成镜像部署约 2 秒；`env set --secret` 后 `status`、`env list`、`--json` 均不含密钥；`app set`、`volume add`、`rollback`、`stop`/`start`、`logs`、`apps` 正常；Linux 上用直连方式部署成功。连接诊断：主机不存在、端口不通 → `host_unreachable`，服务器未装 acornfox → `acornfox_missing`，服务未运行 → `server_down`，退出码 3。六个平台（Windows/macOS/Linux × amd64/arm64）编译通过，Windows 下 CLI 相关包 vet 通过、测试可编译（未在 Windows 上实际运行）。Git 来源实测：**CNB 可匿名克隆**；**Gitee 拒绝匿名 HTTPS 克隆**（多个知名公开仓库均要求登录）→ 新增诊断 `source/auth_required`；GitHub 从开发机克隆超时 → `source/clone_timeout`，提示改用国内平台或直接上传。实测修正 4 处：中文系统下“未找到命令”未识别；缺少分阶段进度事件；镜像加速源对不存在镜像返回 403 被误判为超时；需要登录的仓库未单独诊断。遗留：首次部署失败的应用仍会保留（占用一个公共端口），`apps` 中显示为 missing；Windows 实机测试待有 Windows 环境时补。
- **开发机清理**（2026-09-29）：删除 N0 原型、旧 AcornFox 运行环境（tp06a 进程、容器、数据卷、网络、账号、目录）、旧 MVP 的 Caddy/PostgreSQL/BuildKit 容器、预览容器、10 台 acornfox 桌面测试虚拟机及磁盘、约 28 GB 旧构建缓存（磁盘空闲 40 GB → 91 GB）。清理前备份旧 MVP 数据库导出、tp06a 的 SQLite 数据与受保护证据到 `战略项目/devbox-archive-20260929/`（含校验和）。Agent Ops（aiops）只停止并禁用服务、容器和测试虚拟机，数据与磁盘保留，80 端口已释放。k3s PoC 节点 `opencard-dev-01` 保留未动。

- **M0**：存档分支 `archive/acornfox-thin-core-20260929`（提交 `577b5605`）；阿里云测试机 `i-REDACTED` 已销毁。
- **M1**（提交 `ef2ba9ba`）：新目录 `acornfox/`、模块 `github.com/acornfox/acornfox`，只迁入符合战略的代码；Go 产品代码 22.2 万行 → 6.8 万行。
- **M2**（提交 `65a87e2e`）：核心与执行器分离、`internal/peer` 按 UID 校验、删除功能包与 root 辅助进程、SQLite 迁移重排；Go 产品代码 → 5.1 万行。开发机上 `go test ./...` 29 个包通过。M2 的 `peer`、认证和存储写法是 v2 的起点，其余执行层由 N1 取代。
