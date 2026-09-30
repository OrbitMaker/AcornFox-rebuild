# N4 开发机实测与候选收口

日期：2026-09-30。

> 后续更新：2026-10-01 已补空网络回收代码，形成包含两项收口修复的 `77f33…` 候选；最新状态见 [最终候选与待复验](n4-final-candidate-2026-10-01.md)。下文是本轮当时的实测行为，不据代码更新重写历史通过结果。

**当时结论：原服务端候选完成真实 Linux/Docker/Caddy、数据保留及网页验证；修复后的 Mac CLI 完成真实 SSH/Ctrl+C 复测。N4 暂不标记最终候选整体验收通过：修复后的完整源码再次传输被自动权限模式拒绝，最终 Linux 回归尚未执行；应用删除后的空网络自动回收也尚未实现。**

## 1. 两个候选必须分开

| 候选 | 源码清单 SHA-256 | 用途与验证 |
| --- | --- | --- |
| 原服务端候选 | `e6b44ea89161b1e071668709dd0e9bca24231d37ea76d39cd8592205d6e50853` | 开发机实际运行；Linux build/vet/全量 race；20 项功能断言；实际 Docker/Caddy 集成及网页验证 |
| CLI 信号修复后候选 | `1055be9b23ca68a2e64fc381212027f1add6fdbdccc13c15e7db2ee5a87b5aa4` | 六平台重新编译；本地 Ctrl+C 子进程回归；新 Mac CLI 对原兼容 Linux API/proxy 的真实 SSH 验证 |

- 原 Linux 二进制：`945ff1ecb9cd8882edecc713a3f25475e169585cf2806e1e18704874d5df11b2`。
- 新 Linux 二进制（尚未在开发机运行）：`7365a462ce3ec1e0d4497bf3aca109205beb7df748cadf98ff62058c11c96e22`。
- 新 Mac arm64 二进制：`b429c186726616302912f41f8ef80ba7a6a6c8c184a2ca1ae3feb2d73dc7f9f1`。
- 逐文件比较只变动 `cmd/acornfox/main.go` 与新增 `cmd/acornfox/interrupt_test.go`；其他 API、runner、调和器、存储与网页源相同。**源相同不是最终 Linux 完整测试已执行的替代证据。**
- 快照：`.cache/n4-all-fhtng2so/` 与 `.cache/n4-all-5kxxy_ri/`。未提交 commit，未推送。

## 2. 隔离与安全边界

开发机身份已验证为 `ubuntu-MS-7B89 / ubuntu`，Go `1.25.13`，Docker `29.1.3`，Caddy `2.11.4`。

本轮目录为 `/tmp/afn4-Kc3SURkl`，使用独立：
- Docker socket、data-root、exec-root、pidfile；真实 DockerRootDir 核对为该目录下 `docker-data`。
- SQLite、上传目录、runner/API Unix socket、Caddy admin socket和数据目录。
- 公开应用端口范围 19810～19899，回环控制台 19900；没有替换原系统服务。

私有 Docker 禁止修改 iptables/ip6tables、IP 转发及默认桥，测试地址池与现场已有网络不重叠。只读从系统 Docker 导出所需官方基础镜像，加载到私有实例；MySQL 8.4 只拉入私有实例。

内部 CA 禁止安装到系统信任库：先用 Caddyfile `skip_install_trust` 经真实 `caddy adapt` 验证 JSON，再配置本轮实例 `apps.pki.certificate_authorities.local.install_trust=false`。没有修改宿主信任库。

用户明确授权源码传输及独立服务的一次性网页登录。登录 token 不回显、不进入报告。未复制 SSH 私钥、SQLite 凭据或完整容器环境到本地证据。

## 3. Linux 全量与真实集成测试

原服务端候选：

```text
GOTOOLCHAIN=go1.25.13 go build ./...                         exit 0
GOTOOLCHAIN=go1.25.13 go vet ./...                           exit 0
go test -json -race -count=1 -p 2 ./...                      exit 0
```

20 个有测试的产品包通过，包括 Linux peer 和 runner socket 往返。初轮 Docker/Caddy 用例因未启用开关而 skip，这个结果没有当成实测通过。

随后在私有 Docker/Caddy 上显式设置 `ACORNFOX_DOCKER_IT=1`、`ACORNFOX_CADDY_IT=1`、私有 `DOCKER_HOST`、admin socket 与私有 root CA 路径，再次执行全量 race：**退出码 0**，以下四项均实际通过：
- `TestDockerLifecycle`
- `TestDockerPullImage`
- `TestDockerVolumeLifecycle`
- `TestCaddyIntegration`（严格验证内部 CA HTTPS、HTTP 308、重复同步、解绑清理）

临时暂停的是本轮 server PID，以免其孤儿清理影响直接 Docker 测试；shell trap 恢复了该进程。没有暂停或修改现有系统 AcornFox 服务。

完整日志摘要：`157d9fb9e206014c29b6ef5a73681a26f2675c0bef7f511482fadc566702b3b8`。

## 4. 真正执行的功能断言

`functional-checks.json` 中 20 项检查全部为 passed、complete=true，含恢复过程中重复的服务健康检查；不是 20 个独立产品功能。

| 场景 | 实际验证 |
| --- | --- |
| 源码部署 | 两个 HTTP 样本上传、构建、容器运行、真实 Caddy 路由返回内容 |
| 三种数据库 | PostgreSQL/MySQL 实际 SELECT 1，Redis 实际 PING；Docker healthcheck 均 healthy |
| 私网与资源 | 附加服务不发布端口，与应用同一专用网络；PG/MySQL 512 MiB、Redis 256 MiB |
| 自动重新部署 | 已上线应用添加附加服务后产生新部署，连接变量实际生效 |
| 持久化 | 文件及数据库 marker 在重新部署后保留；Redis AOF 数据也保留 |
| 停止/启动 | 实际应用容器停止、再启动恢复 HTTP；附加服务保持运行 |
| 重启 | 同一容器 ID，启动时间变化，文件与数据库数据仍在 |
| 删除/重加服务 | 三种服务各自保留卷，恢复后沿用原凭据，读取原 marker |
| 删除应用 | 默认保留全部测试卷；显式 `volumes=true` 真正删除受管保留卷 |
| 凭据缺失 | 同名重建应用发现数据库卷但缺旧凭据，返回 `addon_data_orphaned`，不生成错误新密码 |
| 日志脱敏 | 使用不可认证的合成秘密值和 `.invalid` 连接串，日志/批次/API 读出不包含这些值；未将有效数据库密码写入原始日志 |
| 指标 | 实际主机内存/磁盘/CPU及容器内存、限制、CPU值；停止时指标 unavailable |

测试 HTTP 应用只输出就绪与 marker，不输出 DATABASE_URL/REDIS_URL。五个 `addon/*` 失败码及 runner 不可用门控由已有单元测试覆盖，本轮没有对五种故障各制造一次实机失败。

## 5. 真实 Mac→SSH 与网页

使用系统 OpenSSH，严格既有主机指纹校验，临时 HOME/targets.json，不修改用户真实目标或 SSH 配置。

### 旧 CLI 的问题及修复

旧候选常规只读命令通过、重复日志保留，但 SIGINT 为 `-2`。根因是客户端入口用 `context.Background()`，没有把操作系统中断接入跟随循环的取消上下文。

修复：客户端分支 `signal.NotifyContext`，支持 Interrupt/SIGTERM；defer 释放信号订阅和连接。新增实际子进程 SIGINT 回归，本地 race 通过，六平台重编译通过。

新 Mac CLI 真实 SSH 复测 **12 次执行全部退出 0**，包括：
- version/status/apps/addons/stats/env list/logs tail/since。
- 至少 3 条相同 `n4-repeat` 日志保留。
- SIGINT 正常退出 0。
- 下一条 stats 仍 available=true，无本轮 CLI/SSH 残留。

证据 `.cache/n4-ssh-ui/run-xo8dy7vu/result.json` 明确列新 Mac CLI 对原兼容 Linux API/proxy，不声称新 Linux 客户端已运行。旧失败保留于 `run-le0k8878`。

### 真实网页

真实独立服务＋SSH 隧道＋Chrome **8 项通过**：一次性登录后 URL 移除 token、两个真实应用与容器指标、PG/Redis健康及公有字段、轮询保持焦点/滚动、重复日志追加、暂停停止日志请求、浅色400px无横向溢出、无JS异常。

证据 `.cache/n4-ssh-ui/run-pocr46ka/`：`browser-result.json` 与三张真实截图，主会话和子代理均已实际查看。不是模拟 API 或样本 SQLite。

## 6. 清理与保护

- 测试应用及数据卷的删除验收完成。
- 私有实例两个无容器连接的空网络按已核验字面量名单 `af-n4pg`、`af-n4mysql` 清理。
- **网络清理由验收驱动执行；产品删除应用后当前会留下空专用网络，不能把驱动清理记作产品自动回收已实现。**
- 私有 dockerd/Caddy/runner/server 均正常退出，测试端口关闭；Chrome/隧道关闭。
- 系统 Docker 的 116 个原容器 ID、名称全部保持，未删除任何原有容器或数据。
- 保留私有证据目录，不复制其中 SQLite、CA私钥或完整容器环境到共享报告。

## 7. 剩余收口

1. 最终 `1055…` 候选完整传输、Linux build/vet/race，以及最终 Linux CLI 信号测试。再次传输被重新活跃的自动权限分类器拒绝，命令未执行；不能分片或换工具绕过。
2. 应用删除后的空受管网络自动回收需补齐或明确为产品限制；当前网络由验收驱动手工清理。

在以上收口完成前，N4 保持进行中，不借原候选通过证明新候选完整验收。

## 证据入口

- 本地取回的已点名日志/JSON：`.cache/n4-devbox-evidence/`。
- 原/新候选快照及六平台摘要：`.cache/n4-all-fhtng2so/`、`.cache/n4-all-5kxxy_ri/`。
- Mac SSH/浏览器证据：`.cache/n4-ssh-ui/run-le0k8878/`、`run-pocr46ka/`、`run-xo8dy7vu/`。
- 远程保留目录：`/tmp/afn4-Kc3SURkl/`。
