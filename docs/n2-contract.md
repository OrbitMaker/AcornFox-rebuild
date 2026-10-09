# N2 实现契约（开发用）

上层依据：迁移清单第 3.5 节（访问方式：默认 SSH）、第 3.10 节、第 5 节 N2 行。N1 契约见 `n1-contract.md`。

## 0. 目标与完成标准

用户电脑上的 `acornfox` CLI（Windows / macOS / Linux）经 SSH 对服务器完成部署并拿到网址或诊断；AI 工作台可以用 `--json` 稳定解析每条命令的输出。三个平台都能交叉编译；macOS 与 Linux 实测对开发机部署成功，Windows 至少编译通过并跑单元测试（开发机上 `GOOS=windows go test -c`）。

## 1. 连接方式（关键设计）

```
CLI ──exec──> ssh [-p port] [-i key] user@host acornfox proxy
                         │ stdin/stdout = 一条字节流
服务器：acornfox proxy ──> /run/acornfox/api.sock（server 的 Unix socket）
```

- CLI 调用系统自带的 `ssh`（Windows 10+、macOS、Linux 都有），因此自动复用用户已有的 `~/.ssh/config`、密钥和 ssh-agent，不引入 Go SSH 库，不保存密码。
- CLI 把 ssh 子进程的 stdin/stdout 包装成一个 `net.Conn`，作为 `http.Transport.DialContext` 的返回值；HTTP/1.1 keep-alive 复用这一条连接，**一条 CLI 命令只建立一次 SSH**（`MaxConnsPerHost=1`）。
- ssh 参数固定追加：`-o BatchMode=yes`（不在 AI 工作台里卡在密码提示）、`-o ServerAliveInterval=15`、`-T`；stderr 收集起来用于诊断。
- `acornfox proxy [-socket /run/acornfox/api.sock]`：连到 socket，双向拷贝 stdin/stdout，任一方向结束即退出。
- **server 改为监听 Unix socket**：`-listen unix:/run/acornfox/api.sock -listen-group acornfox-users`，socket 0660、属组 `acornfox-users`。能 SSH 登录且在该组中的用户才能使用 AcornFox；服务器上其他本地用户连不上。（N1 的 `127.0.0.1:18800` 保留为可选，N3 的网页控制台隧道使用，届时加登录。）`-listen` 可重复，同时监听多个地址。
- 开发与测试用的直连方式：target 可以是 `url: http://127.0.0.1:18800`（不经 SSH）。

### 连接诊断（stage=`connect`）

| code | 条件 | hint |
| --- | --- | --- |
| `ssh_missing` | 本机找不到 ssh | 安装 OpenSSH 客户端（Windows：设置 → 可选功能） |
| `host_unreachable` | ssh 报 Could not resolve / Connection refused / timed out | 检查地址、端口、安全组是否放行 22 |
| `auth_failed` | ssh 报 Permission denied | 先在终端里 `ssh user@host` 确认能免密登录（`ssh-copy-id`） |
| `host_key_unknown` | Host key verification failed | 先手动 `ssh user@host` 一次确认主机指纹 |
| `acornfox_missing` | 远端 `acornfox: command not found` / 127 | 服务器上尚未安装 AcornFox |
| `permission_denied` | proxy 连 socket 被拒 | 把该用户加入 `acornfox-users` 组后重新登录 |
| `server_down` | socket 不存在或拒绝连接 | `systemctl status acornfox-server` |
| `version_mismatch` | `GET /v1/status` 的 `api_version` 与 CLI 不兼容 | 升级 CLI 或服务器 |

## 2. 本地文件

- **目标配置** `<os.UserConfigDir()>/acornfox/targets.json`（0600，目录 0700）：
  `{"default":"my-server","targets":{"my-server":{"ssh":"ubuntu@1.2.3.4","port":22,"identity":"","remote_command":"acornfox proxy","url":""}}}`。`ssh` 可以是 `~/.ssh/config` 里的 Host 别名。
- **项目文件** `<项目目录>/.acornfox`（JSON，不含任何密钥）：`{"target":"my-server","app":"notes"}`。首次成功提交部署后写入；之后在该目录（或其子目录，向上查找）执行命令时自动读取。
- 选择优先级：命令行 `--target/--app` > `.acornfox` > targets.json 的 default；应用名缺省时取目录名规范化（小写、非法字符转 `-`），不合法则报 usage 错误并提示 `--app`。

## 3. 命令（`internal/cli`；`cmd/acornfox/main.go` 只做分派）

全局：`--json`（机器可读，Skill 使用）、`--target NAME`、`--app NAME`。退出码：0 成功；1 操作完成但失败（部署失败，输出含诊断）；2 用法错误；3 连接失败（connect 诊断）；4 服务器返回错误。

| 命令 | 行为 |
| --- | --- |
| `target add NAME --ssh USER@HOST [--port N] [--identity PATH] [--url URL]` | 写入配置，随即测试连接（`GET /v1/status`），成功则设为 default（若尚无 default） |
| `target list` / `target remove NAME` / `target use NAME` | |
| `deploy [DIR]` | 默认当前目录。按 `.dockerignore` 打包（始终排除 `.git/`、`.acornfox`）为 tar.gz；上限 200 MB，超出给出 `upload/too_large` 并提示检查 `.dockerignore`。根目录无 Dockerfile → 本地直接返回 `upload/dockerfile_missing`（不上传）。上传时带 `Idempotency-Key`（内容 sha256 前 16 位），然后等待到终态：人类模式逐行打印事件，`--json` 只在结束时输出一个 JSON 对象。选项 `--port N`、`--health-path P`、`--no-wait`、`--timeout 20m` |
| `deploy --image REF` | 部署现成镜像（如 `nginx:1.27-alpine`） |
| `deploy --git URL [--ref BRANCH_OR_COMMIT]` | 部署公开 Git 仓库 |
| `status [DEPLOYMENT_ID]` | 无参数：当前应用详情（网址、运行状态、当前版本、卷、环境变量键名）；有参数：该部署的状态、诊断与事件 |
| `apps` | 列出服务器上所有应用 |
| `logs [--tail N]` | 当前 live 容器最近 N 行（默认 100，最多 1000） |
| `env set KEY=VALUE [--secret]` / `env unset KEY` / `env list` | 密钥值从不回显；输出提示“下次部署生效” |
| `volume add PATH` / `volume list` | |
| `app set [--memory MB] [--cpu CORES] [--port N] [--health-path P]` | 修改应用设置，下次部署生效（N1 遗留：内存超限提示引用此命令） |
| `rollback` / `stop` / `start` | rollback 等待到终态，同 deploy |
| `proxy [-socket PATH]`、`server …`、`runner …` | 服务器侧子命令 |
| `version` | 客户端版本与 API 版本 |

`--json` 输出统一形状：成功 `{"ok":true, ...数据}`；失败 `{"ok":false,"diagnosis":{stage,code,message,log_excerpt,hint}}`。部署结束的数据：`{"ok":true,"app","deployment_id","version":seq,"url","warnings":[...],"seconds"}`。

人类模式输出用中文，简短：成功最后一行是网址；失败打印 message、hint 与日志片段，并提示“把以上内容交给 AI 修复”。

## 4. server 侧新增（`apiserver`、`state`、`reconcile`、`runner`）

- `GET /v1/status` 增加 `"api_version": 1`。
- `POST /v1/apps/{app}/deployments` 除 tar.gz 请求体外，接受 `Content-Type: application/json`：`{"image":"nginx:1.27-alpine"}` 或 `{"git":"https://...","ref":"main"}`（只允许 `https://` 地址；拒绝带用户名密码的地址）。`Idempotency-Key` 与重复判定同 N1（digest = sha256(image) 或 sha256(git+"#"+ref)）。
- `state`：`source_kind` 增加 `git`（新迁移 0003，放宽 CHECK）。`image` 来源的 SourceRef 为镜像引用。
- `reconcile` build 阶段：
  - `git`：server 进程自己执行 `git clone --depth 1 [--branch ref]`（ref 像 40 位提交哈希时改为 `clone` 后 `checkout`），超时 5 分钟，`GIT_TERMINAL_PROMPT=0`，目标 `<UploadDir>/<id>-src/`；然后打成 `<UploadDir>/<id>.tar.gz`、删源码目录，余下同 upload。失败诊断 stage=`source`：`clone_timeout`（hint：国内服务器访问 GitHub 常超时，可改用 Gitee/CNB 镜像或直接 `acornfox deploy` 上传本地目录）、`repo_not_found`、`ref_not_found`、`git_missing`、`clone_failed`。
  - `image`：`runner.PullImage`。失败诊断 stage=`image`：`pull_timeout`（hint：配置镜像加速）、`image_not_found`、`pull_failed`。
- `runner` 新增 `POST /v1/images/pull` `{app, deployment_id, ref}` → `ImageInfo`：拉取（超时 10 分钟）后打标签 `acornfox/<app>:<id>`；已存在同名标签直接返回。API 接口加 `PullImage(ctx, app, deploymentID, ref string) (ImageInfo, error)`，拉取失败用 HTTP 200 + `{ok:false, failure}`（同 Build）区分用户错误。`ImageInspect` / `RemoveImage` 以 `acornfox/<app>:` 标签作为归属（拉取的镜像没有我们的 label）。
- `GET /v1/apps/{app}/logs?tail=N` → `{"lines":[...]}`（live 容器；无 live 返回 404 `no_live_deployment`）；日志中的密钥值脱敏。
- `PATCH /v1/apps/{app}` `{memory_mb?, cpu_milli?, port?, health_path?}`：memory 64..16384，cpu_milli 100..16000。
- `acornfox server` 支持 `-listen unix:PATH` 与 `-listen-group NAME`（可重复 `-listen`）。

## 5. 验收（开发机 + Mac）

1. Mac 上 `target add devbox --ssh 开发机`（server 在开发机以 unix socket 运行）→ 在样例项目目录 `acornfox deploy` → 拿到网址并能访问；目录里生成 `.acornfox`；再次 `acornfox deploy` 不需要任何参数。
2. `--json` 下成功、构建失败、连接失败三种输出都能被 `python3 -c 'json.load'` 解析且形状符合第 3 节。
3. `deploy --image nginx:1.27-alpine`（或开发机上已有的镜像）成功；`deploy --git` 分别对 GitHub、Gitee、CNB 上的一个公开小仓库各测一次（记录结果，GitHub 超时属于预期诊断）。
4. `env set --secret` 后，`status`、`env list`、`logs`、`--json` 输出中都不出现密钥值。
5. 连接诊断：错误主机、错误端口、服务器未装 acornfox（remote_command 改成不存在的命令）各返回对应 code，退出码 3。
6. `GOOS=windows/darwin/linux` × `amd64/arm64` 全部编译通过；`GOOS=windows go vet ./cmd/acornfox ./internal/cli/...` 通过。
