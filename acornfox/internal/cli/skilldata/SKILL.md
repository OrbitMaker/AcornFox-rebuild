---
name: acornfox
description: 用 AcornFox CLI 把当前项目部署到用户自己的服务器，并处理部署失败、数据库、日志和应用生命周期。用户说“部署”“上线”“发布到服务器”“加个数据库”“看日志”或提到 acornfox 时使用。
---

# AcornFox 部署

AcornFox 把带 Dockerfile 的项目部署到用户自己的 Linux 服务器（经 SSH）。所有命令都加 `--json`，按输出里的 `ok` 字段判断成败。

## 前置检查

1. `acornfox version --json`：确认 CLI 已安装。
2. `acornfox target list --json`：确认已配置服务器。没有时请用户提供 SSH 地址，执行
   `acornfox target add NAME --ssh USER@HOST [--port N] [--identity 私钥路径]`。
   不要自己猜测服务器地址或私钥。

## 部署

```bash
acornfox deploy --json                      # 部署当前目录（需要根目录有 Dockerfile）
acornfox deploy --json --port 3000          # 指定容器监听端口
acornfox deploy --json --git URL [--ref 分支或提交]
acornfox deploy --json --image nginx:1.27-alpine --app my-app
```

`deploy` 默认等到终态才返回（最长 20 分钟，可用 `--timeout` 调整）：

- 成功：`{"ok":true,"url":"http://IP:端口",...}`，把 `url` 告诉用户。
- 失败：`{"ok":false,"diagnosis":{"stage","code","message","log_excerpt","hint"}}`，按下文修复后重新部署。

首次部署后当前目录会生成 `.acornfox`（只记服务器名和应用名，不含凭据），之后的命令无需再指定 `--app`。

## 状态与诊断

```bash
acornfox status --json                 # 应用状态：url、observed_state、current_deployment
acornfox diagnose --json               # 本机最近一次部署的状态、事件和诊断
acornfox diagnose DEPLOYMENT_ID --json # 指定部署
acornfox logs --json [--tail 200]      # 容器日志
```

部署状态：`queued` → `building` → `starting` → `checking` → `routing` → `live`；失败为 `failed`，被新提交取代为 `superseded`。

## 按诊断码修复

| code | 处理 |
| --- | --- |
| `dockerfile_missing` | 按项目类型生成 Dockerfile |
| `too_large` | 补 `.dockerignore`，排除 node_modules、构建产物、大文件 |
| `build_failed` | 读 `log_excerpt`，修依赖或构建命令 |
| `pull_failed` / `pull_timeout` / `image_not_found` | 基础镜像拉不下来：核对镜像名和标签；服务器在中国大陆时请用户配置 Docker 镜像加速 |
| `port_not_listening` | 程序要监听 `0.0.0.0`（不是 127.0.0.1），端口与 `--port` 一致 |
| `container_exited` / `start_failed` | 看 `log_excerpt` 和 `acornfox logs`，修启动命令或缺失的环境变量 |
| `out_of_memory` | `acornfox app set --memory 1024` 后重新部署 |
| `unpersisted_database`（警告） | 数据写在容器里会丢：`acornfox volume add /app/data` |
| `clone_failed` / `clone_timeout` / `repo_not_found` / `ref_not_found` | 核对 Git 地址和分支，仓库必须公开 |

同一个问题修了两次还失败时，停下来把诊断原文交给用户。

## 配置

```bash
acornfox env set KEY=VALUE [--secret] --json   # 密钥值永不回显
acornfox env list --json
acornfox volume add /app/data --json           # 绝对路径，容器重建后数据保留
acornfox app set --port 3000 --memory 512 --health-path /healthz --json
```

改环境变量、数据卷或设置后执行 `acornfox redeploy --json` 生效。

## 数据库与缓存

```bash
acornfox add postgres --json   # 也可以是 mysql、redis
acornfox addons --json
acornfox remove postgres --json [--volumes]
```

添加后会自动重新部署并注入连接变量：postgres、mysql 为 `DATABASE_URL`，redis 为 `REDIS_URL`。代码里从环境变量读取连接串，不要写死。

## 生命周期

```bash
acornfox stop --json
acornfox start --json
acornfox restart --json
acornfox rollback --json        # 回到上一个成功版本
acornfox stats --json           # CPU、内存
acornfox domain add example.com --json
```

`acornfox delete [--volumes]` 和 `remove ... --volumes` 会删除应用或数据，执行前必须得到用户明确同意。

## Dockerfile 要点

- 程序监听 `0.0.0.0:$PORT`，`EXPOSE` 与 `--port` 一致。
- 用多阶段构建和 `.dockerignore` 控制体积（上传上限 200 MB）。
- 需要持久化的数据写到固定目录，再用 `volume add` 挂载。

## 注意

- 中国大陆服务器的域名需要备案；未备案时用 `IP:端口` 访问。
- 不要在命令行或代码里输出密钥值；用 `env set --secret`。
