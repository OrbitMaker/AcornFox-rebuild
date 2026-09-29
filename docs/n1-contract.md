# N1 实现契约（开发用）

上层依据：`docs/acornfox-rebuild-migration-plan.md` 第 3.1～3.10 节。本文件把 N1 拆成可并行实现的四个包，接口以代码为准：

| 包 | 契约文件 | 负责 |
| --- | --- | --- |
| `internal/state` | `types.go` | SQLite 期望状态：迁移、CRUD、幂等创建部署 |
| `internal/caddyroute` | `api.go` | Caddy admin API（Unix socket）同步 `af-*` 服务器 |
| `internal/runner` | `api.go` | runner 进程：Docker SDK 实现 + peer socket 上的 HTTP 服务 + Go 客户端 |
| `internal/reconcile` | `doc.go` + 本文件 | 调和器：驱动部署、收敛实际状态、崩溃恢复、垃圾回收 |
| `internal/apiserver` + `cmd/acornfox` | 本文件 | server 的 N1 HTTP API、`acornfox server` / `acornfox runner` 子命令 |

共同规则：Go 1.25，module `github.com/acornfox/acornfox`；只用标准库 + 已在 go.mod 中的 `modernc.org/sqlite`、`github.com/moby/moby/client v0.6.0`、`github.com/moby/moby/api v1.56.0`、`golang.org/x/sys`，不新增依赖。Mac 上不编译 Go；在开发机 `yanyan-devbox` 上用 `/tmp/af_rb.sh "<cmd>"` 编译测试（见各任务说明）。每个包自带单元测试并通过 `go test -race`。代码注释用英文，用户可见的诊断 message / hint 用中文。

## 1. 命名（唯一来源：`runner/api.go`）

- 容器 `af-<app>-<部署ID>`，镜像 `acornfox/<app>:<部署ID>`，网络 `af-<app>`，数据卷 `af-<app>-<n>`（由 state 分配，n 从 1 递增，永不复用）。
- 所有受管对象带标签 `acornfox.managed=1`、`acornfox.app`、（容器与镜像）`acornfox.deployment`、（容器）`acornfox.role`。没有 `acornfox.managed=1` 的对象一律不读不改。
- 部署 ID：12 位小写十六进制随机数。应用名：`^[a-z][a-z0-9-]{0,38}[a-z0-9]$`。

## 2. 调和器

### 2.1 调度

- `reconcile.New(Config{Store, Runner runner.API, Router caddyroute.Router, Probe, UploadDir, Logger, Tick 30s, HealthTimeout 60s, Clock})`；`Run(ctx)` 阻塞运行；`Kick(app)` 非阻塞触发某应用一轮（合并重复触发）。
- 每个应用一个 goroutine（首次 Kick 时创建），同一应用的轮次严格串行。启动时和每个 Tick：对 `ListApps` 中每个应用 Kick，并做一次全局孤儿清理（2.5）。
- 全局构建信号量容量 1：任意时刻最多一个 `runner.Build` 在执行。等待信号量时要能被 ctx 取消。
- 每轮开始先 `runner.Ping`；失败则记录事件 `runner/unavailable`（同一应用同一原因 1 分钟内不重复写事件），待处理部署保持原状态，本轮结束，等下一个 Tick。

### 2.2 一轮的步骤（app = 应用名）

1. 读 `GetApp`、`PendingDeployments`、`ListContainers(app)`、`ListEnv`、`ListVolumes`。
2. **取代**：若有多个待处理部署，只保留最新的一个；其余置为 `superseded`（事件："被更新的提交取代"），删除它们的容器（若有）和上传文件。
3. **推进**唯一的待处理部署 d（见 2.3），直到它成为 `live` 或 `failed`，或因 runner 不可用而暂停。
4. **收敛**（见 2.4）。
5. **回收**（见 2.5 的应用级部分）。

### 2.3 推进部署（每个阶段先把状态写入 store 再执行，保证崩溃后能从状态继续）

- `queued` → 置 `building`，`Attempts+1`（`UpdateDeployment` 中完成）后执行构建：
  - `SourceUpload`：获取构建信号量，`runner.Build{App, ID, ContextPath: SourceRef}`。`OK=false` → `failed`，诊断取 `Failure`（阶段 build/upload）。
  - `SourceImage`：`runner.ImageInspect(app, SourceRef)`；不存在 → `failed`（`build/image_missing`，"回退目标版本的镜像已被清理"）。
  - 成功：写 `ImageID`；镜像 `Volumes` 中每个路径 `AddVolume(auto=true)`（事件："自动保存数据目录 <path>"）。
- 重启后遇到 `building`：若 `Attempts >= MaxBuildAttempts` → `failed`（`build/interrupted`，"构建被中断两次"）；否则 `Attempts+1` 再构建一次（runner 对已存在的同名镜像直接返回，所以已完成的构建不会重做）。
- `starting`：确定端口：`app.Port`，否则镜像 `ExposedPorts[0]`，否则 8080（事件提示"未声明 EXPOSE，按 8080 处理"）。对每个 volume `EnsureVolume`；`EnsureContainer{Image: ImageID 或 tag, Env: ListEnv 全部, Mounts, MemoryMB, CPUMilli}`。失败 → `failed`（`start/start_failed`，附容器日志）并删除该容器。成功 → 置 `checking`。
- `checking`：在 `HealthTimeout` 内每 1 秒：`ListContainers` 取该容器；若 `RestartCount>0` 或 `Restarting` 或非 running → `failed`（`health/container_exited`，OOMKilled 时 code 为 `health/out_of_memory`，hint 提示调整内存上限）；否则 `Probe(ctx, "127.0.0.1:<HostPort>", HealthPath)`，返回 nil 即健康。超时 → `failed`（`health/port_not_listening`，hint 含端口）。失败时附最近 40 行日志（先脱敏）并删除该容器。健康后调用 `runner.Diff`，有数据库文件 → 追加警告 `data/unpersisted_database`（message 列出文件，hint：`acornfox volume add <所在目录>`），不阻止上线。置 `routing`。
- `routing`：计算全部应用的期望路由（见 2.4，其中本应用上游换成 d 的容器），`Router.Sync`；失败 → 保持 `routing` 并在下一轮重试（事件 `route/sync_failed`），连续失败超过 5 分钟 → `failed`（`route/route_failed`）并删除 d 的容器。成功 → `SetCurrentDeployment(app, d.ID)`；删除上传文件；事件："已上线 http://<公共主机>:<PublicPort>"。
- 所有进入 `failed` / `superseded` 的部署都删除上传文件；旧的 live 继续服务不受影响。
- 脱敏：诊断和事件中出现的任何 `Secret=true` 环境变量值（长度 ≥ 4）替换为 `******`。

### 2.4 收敛实际状态

- 期望容器集合 = {当前 live 部署的容器} ∪ {待处理部署 d 在 `starting/checking/routing` 时的容器}。
- 其他带 `acornfox.app=<app>`、`role=app` 的容器：删除（事件："清理旧容器 <name>"）。这一步覆盖“已切流量、未删旧容器”的崩溃点。
- `Desired=running`：live 容器缺失 → 用 live 部署的 ImageID 重新 `EnsureContainer`（事件："容器缺失，已重建"）；已停止 → `StartContainer`。`Desired=stopped`：live 容器在运行 → `StopContainer`。
- 路由：每轮用 `ListContainers` 观察到的 live 容器 `HostPort` 计算全部路由（Desired=stopped 或无 live 的应用不出路由），与 `Router.Current` 比较，不同才 `Sync`。server 启动后第一轮总是 `Sync` 一次。

### 2.5 回收

- 应用级：`KeptImageDeployments` 之外、且不是待处理部署的 `acornfox/<app>:*` 镜像 → `RemoveImage`（忽略"镜像仍被使用"的错误）。
- 全局（每 Tick 一次）：`ListContainers("")` 中 `acornfox.app` 不在 `ListApps` 里的容器 → 删除（孤儿）。**数据卷永远不自动删除。** 上传目录中不属于任何待处理部署、且修改时间超过 1 小时的文件 → 删除。

### 2.6 探测

`Probe(ctx, hostport, path) error`：HTTP GET，单次超时 2 秒，不跟随重定向；收到任何状态码 < 500 的响应即健康。

## 3. server 的 N1 HTTP API（`internal/apiserver`）

N1 只供开发机验收与 N2 的 CLI 对接；**N1 无认证，只允许监听 127.0.0.1 或 Unix socket**（启动时拒绝其他地址）。认证与 SSH 接入在 N2/N3。JSON 响应；错误体 `{"error":{"code","message"}}`。

| 方法与路径 | 说明 |
| --- | --- |
| `POST /v1/apps/{app}/deployments` | 请求体为项目目录的 tar.gz（上限 200 MB）；可选头 `Idempotency-Key`。流程：校验应用名 → `EnsureApp` → 流式写入 `<UploadDir>/<临时名>`（0640）并计算 sha256 → `CreateDeployment` → 新建时把文件改名为 `<部署ID>.tar.gz`，重复时删除临时文件 → `Kick` → 202 `{deployment}`（重复提交返回 200 和已有部署）。可选查询参数 `port`、`health_path` 更新应用。 |
| `POST /v1/apps/{app}/rollback` | 以最近一个 `retired` 且有 ImageID 的部署建新部署（`SourceImage`，SourceRef=其 ImageID），202。无可回退版本 → 409。 |
| `GET /v1/deployments/{id}` | 部署 + 事件（查询参数 `after` 事件 ID）。 |
| `GET /v1/apps`、`GET /v1/apps/{app}` | 应用列表 / 详情（含 live 部署、URL、观察到的容器状态、卷列表、环境变量键名与是否密钥——**密钥值永不返回**，非密钥值返回）。 |
| `PUT /v1/apps/{app}/env/{key}` | `{value, secret}`；`DELETE` 同路径删除。只改期望状态，下次部署生效（响应中注明）。 |
| `POST /v1/apps/{app}/volumes` | `{path}`，绝对路径，下次部署生效。 |
| `POST /v1/apps/{app}/stop`、`/start` | 修改 Desired 并 Kick。 |
| `GET /v1/status` | `{runner: ok|unavailable, docker_version, apps: n}` |

URL = `http://<-public-host>:<PublicPort>`。

## 4. 命令（`cmd/acornfox`）

在现有 CLI 的参数解析之前分派：

- `acornfox server -data-dir /var/lib/acornfox -listen 127.0.0.1:18800 -runner-socket /run/acornfox/runner.sock -runner-uid <uid> -caddy-admin /run/acornfox/caddy-admin.sock -public-host <ip>`：打开 state（`<data-dir>/acornfox.db`，上传目录 `<data-dir>/uploads`），建 runner 客户端、Caddy 路由器、调和器、API；SIGTERM 优雅退出。
- `acornfox runner -socket /run/acornfox/runner.sock -server-uid <uid> -socket-gid <gid>`：连接 Docker（`client.FromEnv`），在 peer socket 上服务。
- `-runner-uid` / `-server-uid` 省略时默认当前进程 UID（开发机单账号验收用）；正式安装由 systemd 单元传入。

## 5. 验收（N1 完成标准，开发机实测）

1. 强杀：在 queued / building / starting / checking / routing / 切换后未删旧容器 这 6 个时间点分别 `kill -9` server 或 runner 再启动，最终：部署为 live 或带诊断的 failed，恰好 1 个 live 容器，无残留容器，网址可访问。
2. 防重复：同一 `Idempotency-Key` 或相同内容连续提交 2 次 → 1 个部署、1 个容器；快速连续提交 3 个不同版本 → 只构建最后一个，前两个 superseded。
3. 数据卷：`VOLUME /data` 自动保存；写入文件 → 重新部署 → 回退，文件都在。写 SQLite 到未保存目录 → 出现 `data/unpersisted_database` 警告。
4. 不中断：重新部署期间每 100ms 探测，全部 200。
5. 隔离：一个无 AcornFox 标签的容器在全部测试前后状态不变。
6. 资源上限：容器 `Memory=512MB`、`NanoCPUs=1e9`、日志轮转生效；超内存的应用报 `health/out_of_memory`。
