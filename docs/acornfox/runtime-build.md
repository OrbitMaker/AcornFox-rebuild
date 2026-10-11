# 服务器端运行依赖：Docker 与 Caddy

[cc] 2026-10-11 重写。AcornFox 自己不构建、不修改任何运行时组件。服务器上只依赖两样现成的东西，都由 `scripts/install/install.sh` 安装：

| 组件 | 用途 | 来源 |
| --- | --- | --- |
| Docker Engine | 构建应用镜像、运行应用与附加服务容器 | Docker 官方 apt 源或其国内镜像；都不可用时退回发行版仓库的 `docker.io` |
| Caddy | 应用的公网入口、自动 HTTPS、控制台公网访问 | Caddy 官方发布的 Linux 二进制，版本固定在 `install.sh` 的 `CADDY_VERSION` |

`acornfox runner` 通过 Docker API 构建和运行容器，不调用 `docker` 命令，也不依赖 buildx。`acornfox server` 通过 Caddy 的管理接口（Unix socket `/run/acornfox/caddy-admin.sock`）增删路由，不改写 Caddyfile。

## Docker

`install.sh` 的 `install_docker` 按顺序尝试下列 Docker 官方源，安装 `docker-ce`、`docker-ce-cli`、`containerd.io` 等官方包：

1. 阿里云、腾讯云服务器优先使用云厂商内网镜像（不走公网流量）；
2. 中国大陆依次尝试阿里云、腾讯云、清华大学的 `docker-ce` 镜像；
3. 其他地区使用 `download.docker.com`。

某个源的索引不可用（镜像站正在同步）就换下一个；全部失败时安装发行版仓库的 `docker.io`。已装好 Docker 的服务器可以用 `--skip-docker` 跳过。

中国大陆的服务器还会配置 Docker Hub 镜像加速。默认是公共加速地址；阿里云用户应改用控制台“容器镜像服务 → 镜像加速器”中的专属地址，安装时用 `--registry-mirror` 传入。

## Caddy

所有地区都安装 Caddy 官方二进制，不用 apt 源：官方 apt 源（cloudsmith）对匿名请求返回 402，Ubuntu / Debian 仓库里的 Caddy 2.6.2 又不支持 AcornFox 写入的全局选项 `persist_config`（路由不落盘，Caddy 重启后由 `acornfox server` 重新下发）。

下载顺序：

1. 中国大陆先从 AcornFox 的 Gitee 发行版取。每个 AcornFox 发行版都随附同一份 Caddy 官方安装包、官方校验文件和许可证（由 `scripts/build-release.sh` 下载并校验后放进 `dist/`）；
2. 取不到，或在其他地区，从 Caddy 的 GitHub 发行页下载，必要时经 GitHub 加速地址（`ACORNFOX_GITHUB_PROXY`）。

无论从哪里下载，都按 Caddy 官方发布的 SHA-512 校验，校验文件优先直接从 Caddy 官方取，与安装包的来源相互独立。

二进制安装没有 deb 包自带的账号和服务，`install.sh` 会补上 `caddy` 系统账号和 `caddy.service`，并写入一份只有全局选项的 Caddyfile：管理接口只开 Unix socket，`persist_config off`；应用路由全部由 `acornfox server` 通过管理接口下发。

## 升级 Caddy

1. 修改 `scripts/install/install.sh` 中的 `CADDY_VERSION`；
2. 运行 `python3 scripts/gen-licenses.py` 更新许可材料；
3. 在一台全新服务器上分别用国内、境外路径安装验证，然后随下一个 AcornFox 版本发布。

已安装的服务器检测到 `caddy` 已存在时不会重装；升级已有服务器上的 Caddy 目前需要手动替换 `/usr/bin/caddy` 后重启 `caddy`。

## 许可

Caddy 以 Apache-2.0 发布，随发行版附带的 `caddy_LICENSE` 是其原文；完整清单见 `docs/licenses/`。Docker 由服务器的软件包管理器安装，不随 AcornFox 分发。
