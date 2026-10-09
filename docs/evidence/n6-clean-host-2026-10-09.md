# N6 干净服务器实测（2026-10-09）

[cc] 2026-10-09。用户授权在阿里云创建抢占式实例做首发前实测。本记录覆盖 N6 验收清单第 1、3（部署链路，未经 AI 工作台）、4、6 项和 N5 升级/回退，**不是**清单要求的"未参与开发的人"独立验收；第 2 项（CLI/Skill 经 Release 安装）、第 5 项（域名 HTTPS）、第 7 项（AI 工作台）未做。

## 环境

| 项 | 值 |
| --- | --- |
| 实例 | `i-REDACTED`，ecs.c6.large（2 核 4 GB），cn-zhangjiakou-a，抢占式，24 小时自动释放 |
| 系统 | Ubuntu 24.04.5 LTS，官方镜像 `ubuntu_24_04_x64_20G_alibase_20260916.vhd`，开机即装，无手工改动 |
| 安全组 | 测试专用 `sg-REDACTED`：TCP 22、80、443、18810-18899 |
| 服务端 | 本地构建 `0.2.0-rc2`（`install.sh --binary`，尚无 GitHub Release） |
| 客户端 | macOS arm64，本地构建 CLI，经 SSH 连接 |

前两台实例（`i-REDACTED`、`i-REDACTED`）用于发现和修复问题，已释放；其结果不作为验收证据。

## 实测中发现并修复的问题

| # | 问题 | 影响 | 修复 |
| --- | --- | --- | --- |
| 1 | 国内 Docker 源在 Docker 29.9.0 发布后不一致：阿里云索引大小不符、腾讯云读包 I/O 错、清华包 404 | 安装直接中止 | `install.sh` 每源重试两次、依次换源，全失败退回发行版 `docker.io`；全失败时删除残留源列表 |
| 2 | 新开云主机 unattended-upgrades 占用 dpkg 锁 | 安装直接中止 | apt 调用统一 `DPkg::Lock::Timeout=600` |
| 3 | Caddyfile `origins *` 被 Caddy 当字面值，拒绝 Host `caddy` | **所有应用路由失败**（403 host not allowed） | 改为 `origins caddy`；其他 Host 仍被拒 |
| 4 | 幂等键命中已失败部署仍原样返回 | 修好环境后同一代码无法重新部署 | 服务端释放已结束部署的键，见 ADR-0010 |
| 5 | 安装未传 `--public-host` | 访问地址显示 `http://:18810` | 安装时从云元数据取公网 IP（校验是 IPv4），可 `--public-host` 覆盖 |
| 6 | 安装/文档未提示安全组 | 云主机默认挡住 18810-18899，用户以为部署坏了 | 安装摘要、README、快速开始写明需放行的端口 |
| 7 | `addon_data_orphaned` 未给出路 | 用户卡住 | 提示补充 `delete --volumes`（会永久删数据） |

另：安装、升级、CLI 脚本下载二进制改为按 Release 的 `SHA256SUMS` 校验，Caddy 按官方 SHA-512 校验；`curl | sudo bash` 时设 `DEBIAN_FRONTEND=noninteractive`。

## 结果（第三台，最终脚本 sha256 `6bb12e97…`）

| 检查 | 结果 |
| --- | --- |
| 一条命令安装 | exit 0；Docker 29.9.0（腾讯源第 2 次重试成功）、Caddy 2.8.4、server/runner/caddy/docker 全部 active；3 个 socket 属主权限正确；10 分钟内无 warning 日志 |
| 首次部署（Dockerfile 项目） | 24 秒上线，输出 `http://<server-ip>:18810`，公网访问返回应用内容 |
| 失败诊断 | 启动即退出的版本：判失败，诊断"容器启动后退出或反复重启"并附日志片段；旧版本继续服务 |
| 附加服务 | `add postgres`：healthcheck 通过，5432 不对外发布，应用容器注入 `DATABASE_URL` 并可写入数据 |
| 生命周期 | stop（约 5 秒后停止，访问中断）/ start / restart / redeploy 后数据保留 |
| 日志与指标 | `logs --tail` 返回访问日志；`stats` 返回主机资源 |
| 附加服务删除重加 | 默认保留卷，重新添加后旧数据仍在 |
| 删除应用 | 默认保留数据卷、回收网络；同名重加报 `addon_data_orphaned`；`delete --volumes` 清除数据卷 |
| 升级 rc2→rc3 | 备份、迁移、替换、重启、验证通过；期间 21 次探测全 200 |
| 故意破坏升级 | 假二进制启动失败，自动恢复二进制和数据库，回到 rc3；期间 61 次探测全 200 |

## 发布后正式路径（v0.2.0 + Gitee 镜像）

v0.2.0 发布到 GitHub 后，张家口测试机直连 GitHub 下载约 10 KB/s：`upgrade.sh` 6.5 分钟，`install-cli.sh` 超过 20 分钟未完成。按用户选定方案建 Gitee 镜像 `VIP13390/AcornFox-rebuild`（ADR-0011）后：

| 检查 | 结果 |
| --- | --- |
| Gitee 匿名下载 | 13 MB 二进制 6.5 秒（约 2 MB/s），SHA256 通过；Gitee 发行版 API 可匿名取最新版本 |
| `install-cli.sh`（Gitee 优先） | 8 秒完成并通过校验 |
| `upgrade.sh`（Gitee 优先） | 15 秒；首次因 ip-api 超时误判为境外，改为先查云元数据并沿用安装时判断后通过 |
| 全新实例 `i-REDACTED` 原样执行 README 国内命令 `curl -fsSL https://gitee.com/VIP13390/AcornFox-rebuild/raw/main/scripts/install/install.sh \| sudo bash` | exit 0，355 秒；其中 Docker 约 5 分钟（阿里云 Docker 源仍不一致，重试后换腾讯源），Caddy 经 ghfast 约 40 秒，AcornFox 从 Gitee 约 8 秒 |
| 发布版 macOS CLI（`dist/acornfox_darwin_arm64`，v0.2.0） | 首次连接按设计要求先确认主机指纹；`deploy` 11.6 秒上线，公网访问正常 |

### 安装耗时优化（同日）

上面 355 秒的分解：原以为慢在 Docker，按 apt 日志实测是 `install.sh` 把阿里云镜像自带的内网源 `mirrors.cloud.aliyuncs.com` 当成"非国内源"替换成公网 `mirrors.aliyun.com`（正则 `mirrors\.[a-z]+\.com` 匹配不到两级子域），冷启动 `apt-get update` 由 17 秒变为 251 秒（同为 203 MB 索引）。修复：只在源指向境外官方地址时替换，并停用指向官方地址的 deb822 `*.sources`；Docker 在阿里云/腾讯云先用内网源（GPG 密钥仍经 https 获取），索引不一致直接换源不重试。

全新实例 `i-REDACTED` 管道执行：**110 秒**（原 355 秒）。apt update 18 秒、基础依赖 5 秒、Docker 22 秒（阿里云内网源首次成功）、Caddy 50 秒（GitHub 直连低速中止后经代理）、AcornFox 8 秒（Gitee）。腾讯云内网 Docker 源未实测。

## 仍待完成

- GitHub 正式路径（`releases/latest/download/install.sh`）在境外服务器上的全新安装未测；v0.2.0 附件里的脚本不含 Gitee 与低速换源，需发布 v0.2.1 才对 GitHub 路径生效。
- 第 5 项域名 HTTPS / 未备案提示：需要一个解析到测试机的域名。
- 第 2、7 项 Skill 与 AI 工作台；由未参与开发的人完成独立验收。
- 小问题：`stop` 在容器实际停止前就打印"已停止"；`upgrade.sh` 摘要打印原始颜色转义码；国内 GitHub 直连下载 Caddy 很慢（前两台约 10 分钟，第三台走 ghfast 代理较快）。
