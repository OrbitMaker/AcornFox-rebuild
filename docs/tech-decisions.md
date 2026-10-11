# 技术决策记录 (ADR)

本文档记录 AcornFox-rebuild 项目的重要技术决策,帮助团队理解"为什么这样做"。

## 格式

每个决策包含:
- **编号**: ADR-XXXX
- **日期**: 决策日期
- **状态**: 提议 / 接受 / 废弃 / 被 ADR-YYYY 取代
- **背景**: 面临的问题或需要决策的场景
- **决策**: 选择的方案
- **理由**: 为什么选择这个方案
- **后果**: 这个决策的影响(好的和坏的)
- **替代方案**: 考虑过但未采纳的其他方案

---

## ADR-0001: 状态记在 AcornFox,运行交给 Docker

**日期**: 2026-09-29  
**状态**: 接受  
**决策者**: 产品负责人

### 背景

需要决定 AcornFox 如何管理应用容器的生命周期和状态。

### 决策

- SQLite 记录"应该是什么样"(期望状态)
- Docker 标签反映"实际是什么样"(实际状态)  
- Runner 通过调和器让两者一致
- 容器设为 `unless-stopped` 自动重启,AcornFox 停止不影响应用

### 理由

1. **职责分离**: Docker 擅长运行容器,我们不需要重新实现
2. **可靠性**: 容器由 Docker 托管,AcornFox 升级或崩溃不影响应用
3. **调和模型**: 声明式管理,幂等且易于恢复
4. **简化复杂度**: 不需要自己实现进程监控、重启策略

### 后果

**好处**:
- AcornFox 可以放心升级,不担心应用中断
- 崩溃后重启能自动收敛到正确状态
- 实现更简单,减少 Bug

**代价**:
- 依赖 Docker,不能在没有 Docker 的环境运行
- 需要处理 Docker 本身的故障情况

### 替代方案

- **自己管理进程**: 复杂度高,可靠性难保证
- **使用 systemd**: 限制部署灵活性,无法隔离

---

## ADR-0002: 只保留一道权限边界

**日期**: 2026-09-29  
**状态**: 接受  
**决策者**: 产品负责人

### 背景

需要决定哪些组件可以访问 Docker,以及如何防止权限扩散。

### 决策

- 只有 runner 能访问 Docker
- runner 运行在独立账号 `acornfox-exec`,属于 `docker` 组
- server 只通过 Unix socket 调用 runner,传递类型安全的请求
- server 被攻破不直接获得 Docker 访问权限(等同 root)

### 理由

1. **最小权限原则**: 缩小攻击面
2. **深度防御**: 即使 server 被攻破,攻击者仍需突破 socket 权限校验
3. **审计清晰**: 所有 Docker 操作都经过 runner,易于追踪

### 后果

**好处**:
- 提高安全性,减少单点失败风险
- 权限边界明确,易于审计

**代价**:
- 需要维护 socket 通信和权限校验代码
- 部署时需要创建两个账号和配置权限

### 替代方案

- **server 直接访问 Docker**: 简单但不安全
- **使用 rootless Docker**: 增加部署复杂度,兼容性问题

---

## ADR-0003: 默认只走 SSH,管理接口不对公网开放

**日期**: 2026-09-29  
**状态**: 接受  
**决策者**: 产品负责人

### 背景

需要决定 AcornFox 控制台的访问方式,在便利性和安全性之间平衡。

### 决策

- server 默认只监听 `127.0.0.1`
- CLI 通过 SSH 访问服务器,在 SSH 通道里调用 server
- `acornfox open` 建立 SSH 隧道并打开浏览器
- 可选公网 HTTPS(绑定已备案域名后才开放)

### 理由

1. **复用现有认证**: 用户已经配置好 SSH 密钥,无需再管理令牌
2. **默认安全**: 管理接口不暴露,减少攻击面
3. **灵活性**: 高级用户可选择开放 HTTPS
4. **中国特色**: 未备案域名无法对外服务,SSH 是更可靠的方式

### 后果

**好处**:
- 安装后立即可用,无需配置防火墙或域名
- AI 工作台执行 CLI 时无需复制令牌
- 减少账号体系和登录限速的开发工作

**代价**:
- 用户必须配置 SSH 访问
- 移动端访问需要额外配置(通过 SSH 客户端或开放 HTTPS)

### 替代方案

- **默认开放 HTTPS**: 安全风险高,需要强认证
- **只提供 CLI**: 缺少可视化界面,用户体验差

---

## ADR-0004: 附加服务使用固定官方镜像

**日期**: 2026-09-29  
**状态**: 接受  
**决策者**: 产品负责人

### 背景

应用需要数据库时,如何提供?自己打包还是使用官方镜像?

### 决策

- 使用官方镜像的固定版本: `postgres:16-alpine`, `mysql:8.4`, `redis:7-alpine`
- 不做备份、主从复制、版本升级
- 首发只保证"能用、数据不丢于重新部署"

### 理由

1. **可靠性**: 官方镜像经过充分测试
2. **可维护性**: 不需要自己维护数据库补丁
3. **聚焦核心**: 单机版重点是部署便利性,不是数据库托管

### 后果

**好处**:
- 开发工作量小,质量有保障
- 用户熟悉官方镜像,心智负担低

**代价**:
- 功能有限,无备份和主从
- 需要在文档中明确说明限制

### 替代方案

- **自建托管数据库**: 开发量大,首发时间拉长
- **不提供附加服务**: 用户体验差,需要自己配置

---

## N4 决策 (进行中)

### ADR-0005: 生命周期期望状态模型

**日期**: 2026-09-30  
**状态**: 接受(已实现,启停在 N2/N3 实测通过)  
**提出者**: [cc]

### 背景

N4 需要实现停止、启动、重启功能,如何在调和模型中表达?

### 决策

使用 `apps` 表已有的 `desired` 字段(migration 0001):
- `running`: 应该在运行
- `stopped`: 应该停止

调和器每轮比对期望与实际,执行最少操作收敛。

### 理由

1. **符合调和模型**: 声明式,幂等
2. **简单**: 只有两个状态,不引入复杂状态机
3. **可恢复**: 崩溃后重启能自动收敛

### 后果

**好处**:
- 代码复用现有调和逻辑
- 重复操作安全(幂等)

**代价**:
- 实际收敛由调和器完成,接口返回时容器可能尚未停止(API 写入期望状态后会立即触发一轮调和)

### 替代方案

- **立即执行**: 需要单独的操作队列,复杂度高

---

### ADR-0006: 附加服务未就绪时应用部署判失败

**日期**: 2026-09-30  
**状态**: 接受  
**决策者**: 产品负责人

### 背景

应用依赖的附加服务（数据库）拉取失败、启动失败或一直没有就绪时，新版本应用即使启动也连不上数据库。如果部署照常推进，失败最终会显示为应用自己的 `health/container_exited` 或 `health/port_not_listening`，用户和 AI 会去查应用代码，方向就错了。

### 决策

- 启动应用新容器前，先等待该应用的所有附加服务就绪。就绪指能接受连接，不只是容器在运行。最多等待 120 秒。
- 未就绪时部署判为失败，旧版本继续服务。诊断阶段为 `addon`，错误码为 `pull_failed`、`start_failed`、`exited`、`out_of_memory`、`not_ready`，与其他错误码一样只能新增、不能改名。
- 诊断要写清楚：message 说明是哪个附加服务、出了什么事、对应用的影响（新版本未启动，原版本继续运行；或应用尚未上线）；日志取自附加服务容器；hint 给出下一步，并说明数据卷未被改动。
- runner 暂时不可用不算附加服务失败，等下一轮重试。

### 理由

1. 诊断指向真正的原因，不会把数据库故障误报成应用故障。
2. 与现有语义一致：部署失败不影响正在服务的旧版本。
3. PostgreSQL 和 MySQL 首次初始化时会先启动临时实例再重启，只看容器状态会误判为已就绪。

### 后果

**好处**: 诊断直接指向附加服务，AI 读到诊断就知道该查数据库日志，而不是应用代码。

**代价**: 首次添加数据库的那次部署，要多等数据库初始化的时间（通常几秒到几十秒）；稳定契约新增 5 个错误码。

### 替代方案

- **部署不等待，由应用自行重试连接**: 实现简单，但数据库真的起不来时，诊断会指向应用，排查方向错误。
- **只看容器是否在运行**: 首次初始化期间会误判为已就绪。

### 实现 (N4.2, [addon-agent])

- 就绪判断用 Docker healthcheck，只探测容器内 127.0.0.1 的 TCP（`pg_isready -h 127.0.0.1`、`mysqladmin ping -h 127.0.0.1`、`redis-cli ping` 经 `REDISCLI_AUTH`）。首次初始化的临时实例只监听 Unix socket 或关闭网络，不会被误判为就绪；密码不出现在进程参数里。
- 门控位于调和器 `doStart`：新应用容器创建前最多等 120 秒；`recreateLive`（重建丢失的在线容器）不等待。
- 凭据明文存于 SQLite `addons.credentials`（服务器管理员可读），任何读接口都不返回；诊断日志按连接地址和裸密码脱敏。
- 尚未在真实 Docker 上验证三种镜像的 healthcheck 与首次初始化行为。

---

## 首发前决策

### ADR-0007: 服务器上的账号、目录与 socket 布局

**日期**: 2026-10-02  
**状态**: 接受（install.sh / upgrade.sh 已实现，测试服务器手工验证上传可读）  
**提出者**: [cc]

#### 背景

首发验收时部署全部失败，报“无法读取上传的项目包”。原因是 server（acornfox）写出的上传包为 0640 acornfox:acornfox，runner（acornfox-exec）不在该组，读不到。排查中还发现：`/run` 是 tmpfs，重启后 `/run/acornfox` 消失；手工把它改成 acornfox-exec 所有后，Caddy 重启时又建不了 admin socket。

#### 决策

三个服务账号共用一个通信组 `acornfox-ipc`（成员：acornfox、acornfox-exec、caddy），权限靠目录控制，不靠文件：

| 路径 | 所有者 | 权限 | 说明 |
| --- | --- | --- | --- |
| `/var/lib/acornfox` | acornfox:acornfox-ipc | 0710 | 组只能穿过，看不到数据库 |
| `/var/lib/acornfox/uploads` | acornfox:acornfox-ipc | 2750 | runner 只读上传包 |
| 上传包 `uploads/*.tar.gz` | acornfox | 0644 | 外层目录已挡住其他本地用户 |
| `/run/acornfox` | root:acornfox-ipc | 2771 | 由 `/etc/tmpfiles.d/acornfox.conf` 开机重建；setgid 让新 socket 继承组；其他用户只能穿过 |
| `api.sock` | acornfox:acornfox-users | 0660 | `server --listen-group acornfox-users`；SSH 用户为 root 或加入 acornfox-users |
| `runner.sock` | acornfox-exec:acornfox-ipc | 0660 | 另有对端 UID 校验，只接受 server |
| `caddy-admin.sock` | caddy:acornfox-ipc | 0660 | 只有服务账号能改路由 |

Caddy 的 admin 接口为 `unix//run/acornfox/caddy-admin.sock|0660`，`persist_config off`，路由完全由 AcornFox 每次同步时写入。

CLI 用户单独用 `acornfox-users` 组：若让 SSH 用户加入 acornfox-ipc，他们就能直接改 Caddy 路由，权限超出 API 本身。

#### 理由

1. 不需要任何服务以 root 运行，也不需要账号互加对方的主组。
2. 文件权限出错（umask、Chmod 遗漏）时，目录仍是第二道防线。
3. tmpfiles.d 是 systemd 发行版上重建 `/run` 子目录的标准做法。

#### 后果

**代价**: 上传包本身对“能进入目录的人”可读；这些人只有三个服务账号和 root。

#### 替代方案

- **runner 加入 acornfox 主组**: 会让 runner 读到数据库，违背 ADR-0002 的单一权限边界。
- **server 把包通过 socket 流给 runner**: 更干净，但要改 runner 协议，首发前不做。

### ADR-0008: Skill 采用 SKILL.md 目录格式，诊断命令 `diagnose`

**日期**: 2026-10-02  
**状态**: 接受  
**提出者**: [cc]

#### 决策

- Skill 是带 `name`/`description` frontmatter 的 `SKILL.md`，源文件 `acornfox/internal/cli/skilldata/SKILL.md`（嵌入二进制），仓库根 `skills/acornfox/SKILL.md` 为同步副本，测试保证一致。
- `acornfox skill install` 自动安装到已检测到的 Claude Code（`~/.claude/skills/acornfox/SKILL.md`）和 Codex（`~/.codex/skills/acornfox/SKILL.md`）；其他工具用 `--dir` 指定目录或 `skill print` 输出内容。原先写死的 Cursor、Windsurf、MarsCode、通义灵码路径未经核实，已去掉。
- 新增 `acornfox diagnose [DEPLOYMENT_ID]`：不带 ID 时查本机最近一次提交的部署。记录存在用户配置目录 `acornfox/last-deployments.json`，不写进项目里的 `.acornfox`，避免每次部署都改动用户仓库。

---

### ADR-0009: 张家口测试控制台的公网 HTTPS 接入

**日期**: 2026-10-04

**状态**: 接受，当前测试机实测通过

**提出者**: [codex]

#### 背景与决定

用户明确要求当前张家口测试机控制面板可通过公网浏览器访问。原生控制台在 loopback 提供页面，登录通过 SSH 取得一次性令牌；直接对外反代页面不能完成浏览器登录。

以 `https://panel.acornfox.com` 提供独立公网入口：Caddy bcrypt 认证后，将已认证管理员标记传入私有 Unix socket 网关；网关仅在首页为用户内部签发、兑换原生令牌，返回 Secure、HttpOnly、SameSite=Strict 的原生会话 Cookie。公网不接触令牌签发接口，继续使用原生会话和 CSRF；写请求额外要求精确 HTTPS Origin。令牌不出现在公网地址、响应正文或日志。

可信 API 保持 Unix socket，控制台 18800 保持 loopback。网关使用标准库独立命令和独立 systemd 服务，不调整核心接口、数据库迁移或依赖。Caddy 服务器命名 `public-console`，与调和器管理的 `af-*` 服务器分离；配置保存在 Caddyfile，reload 后入口保留。

#### 代价、边界与回退

增加一个私有网关服务。浏览器缓存 Basic 认证；界面退出仅撤销原生会话，关闭浏览器会话才能结束其缓存的 Basic 认证。网关仅适配当前测试域名；改变域名需要同步配置并重新构建。该操作不构成 N6 首发验收，也没有修复历史业务应用部署失败。

原 Caddyfile 和运行 JSON 已备份；可恢复原配置、停用本次网关、仅按本次 DNS RecordId 删除新记录。凭据保存在仓库外的 0600 文件，运行 Caddyfile 为 root:caddy 0640。实测见 [公网控制台证据](evidence/public-console-2026-10-04.md)。

---

### ADR-0010: 幂等键只对进行中或已上线的部署生效

**日期**: 2026-10-09  
**状态**: 接受  
**提出者**: [cc]

#### 背景

CLI 上传时以内容 sha256 前 16 位作为 `Idempotency-Key`（N2 契约），服务端按 `(app, request_key)` 唯一索引查找，命中即原样返回，不看状态。干净服务器实测：首次部署因 Caddy 管理接口配置错误失败，修好服务器后对未改动的代码再次 `deploy`，0.6 秒返回旧的失败记录，用户无法重试。部署 A → B → 再部署 A 同理会返回已退役的 A，不做任何事。

#### 决策

`CreateDeployment` 命中幂等键时，只有 queued/building/starting/checking/routing/live 的部署原样返回；已结束（failed、retired、superseded）的部署清空其 `request_key`，然后正常创建新部署。与摘要去重（只匹配进行中或已上线）口径一致。CLI 契约和数据库结构都不变。

#### 后果

同一次请求的网络重试仍幂等；失败后修好环境可直接重新部署同一份代码。代价：旧部署记录失去其请求键，按键追溯只能找到最新一次。

#### 替代方案

CLI 每次执行生成随机键：要改 N2 契约，且服务端仍会对其他客户端返回已结束记录，未采纳。

---

### ADR-0011: 中国大陆通过 Gitee 镜像分发

**日期**: 2026-10-09  
**状态**: 接受（用户选定方案 A）  
**提出者**: [cc]

#### 背景

国内测试机实测：直连 GitHub 下载 13 MB 二进制约 10 KB/s，CLI 安装超过 20 分钟，服务端升级 6.5 分钟；直连失败要等满 `--max-time` 才轮到代理。

#### 决策

- Gitee 仓库 `VIP13390/AcornFox-rebuild` 作为国内镜像：代码、标签、发行版附件与 GitHub Release 相同，用同一份 `SHA256SUMS` 校验。`scripts/publish-gitee.sh vX.Y.Z` 在 GitHub 发布后同步。
- 国内安装命令从 Gitee `raw/main` 获取脚本；脚本在中国大陆先查 Gitee 发行版 API 取最新版本（Gitee 的 `releases/latest` 跳转到源码包，不能用），先从 Gitee 下载，失败再走 GitHub 直连与代理。
- 所有下载连续 15 秒低于 50 KB/s 即换源，全部过慢时最后不限速再试一次。
- `install.sh` 把网络环境判断写入 `/etc/acornfox/install.env`，`upgrade.sh` 沿用；无该文件时先查云厂商元数据再查 ip-api（ip-api 实测偶尔超过 2 秒）。

#### 后果

实测 CLI 安装 8 秒、升级 15 秒（Gitee 约 2 MB/s）。代价：发版多一步同步；Gitee 社区版单仓库附件总量 1 GB（每版约 66 MB），旧附件需定期删除；镜像归属个人账号 `VIP13390`。

#### 替代方案

阿里云 OSS/CDN：速度可控但需要流量费，自有域名走国内 CDN 需备案，未采纳（可作后续补充）。

---

### ADR-0012: Skill 是安装入口

**日期**: 2026-10-09  
**状态**: 接受（用户确定）  
**提出者**: [cc]

#### 决策

用户第一步安装的是 Skill，而不是 CLI 或服务端：官网与 README 提供一句可复制的话，让 AI 工作台从 `https://acornfox.com/skill/SKILL.md` 下载 Skill。Skill 的「首次使用」一节负责：分别在用户电脑和服务器上判断网络（ip-api 返回 CN，或查不到国家且直连 GitHub 失败，则走 Gitee，否则走 GitHub），用对应来源安装 CLI 与服务端，再 `target add` 与部署。需要 sudo 密码、确认 SSH 主机指纹的步骤交给用户执行。

官网的 `skill/SKILL.md` 由部署脚本从仓库 `skills/acornfox/SKILL.md` 发布，与 CLI 内置版本保持同一份内容（测试保证一致）。手动 curl 安装保留为备选。

#### 后果

用户不需要先知道自己该用哪个安装命令；电脑与服务器不在同一地区时也能各自选对下载源。代价：Skill 内容决定了安装流程，修改安装方式时需同步 Skill。

---

### ADR-0013: 重新部署记录原始来源与原因

**日期**: 2026-10-09  
**状态**: 接受  
**提出者**: [cc]

#### 背景

重新部署、回退、添加/移除附加服务都复用已有镜像，新部署的 `source_kind` 为 image（执行端据此直接使用镜像而不重新构建）。控制台据此显示「镜像」，用户从目录部署的应用看起来来源变了。

#### 决策

执行用的 `source_kind` 不变；迁移 0006 追加展示用的 `based_on_seq`（基于第几版）、`origin_kind`（原始来源，沿链继承）、`reason`（`redeploy` / `rollback` / `addon_add:<kind>` / `addon_remove:<kind>`）。迁移 0007 为旧记录按「被引用镜像由哪次 upload/git 部署构建」回填 `origin_kind`。0006 已在测试机执行，按规则不修改，补数据另起 0007。

#### 后果

控制台与接口能说明每个版本从哪来、为什么产生。升级前生成的记录只能回填来源，无法回填原因。

---

### ADR-0014: 控制台改为顶栏 + 页面，采用“一拨即开”规范

**日期**: 2026-10-10  
**状态**: 接受（负责人确认）  
**提出者**: [cc]

#### 决策

- 控制台去掉“桌面 + 底部 Dock + 弹出窗口”，改为顶栏 + 四个页面（我的应用、应用中心、服务器、设置），应用详情为独立页面，六个标签（概览、日志、版本记录、配置、数据库、域名）；地址用 `#/…` 片段，刷新不丢位置。手机宽度改为底部标签栏。
- 视觉按 `docs/brand.md`：开关标志、运行青、IBM Plex 字体。字体文件随控制台嵌入（安全策略禁止外部资源），约 160 KB。
- 应用启停用卡片上的开关；数据库标签可直接添加 / 移除附加服务（移除默认保留数据卷）。
- 应用中心页在目录服务上线前只显示“即将开放”和首批应用预告，不做假的安装按钮。
- 继续不依赖框架、不用 `innerHTML`、不内联样式；轮询只替换有变化的节点。

#### 后果

`console/static` 增加 `fonts/` 与 `brand/` 资源；Go 侧只嵌入目录，无需改代码。新增了从控制台添加 / 移除附加服务的入口（接口早已存在，原控制台只读）。

---

### ADR-0015: 应用目录分发走 Gitee + 官网服务器，镜像仓库自建

**日期**: 2026-10-10  
**状态**: 接受（负责人确认），实现待 N8  
**提出者**: [cc]

#### 决策

- 应用目录索引与图标包发布到 Gitee 发行版和官网服务器（已备案），客户端先取官网、失败换 Gitee，与 ADR-0011 换源规则一致。
- 应用镜像放自建镜像仓库：开源镜像仓库服务 + 自建对象存储 + 自建 CDN 节点，不使用阿里云容器镜像服务；云上操作可用主账号。
- 详见 `docs-private/app-center-and-ops-system-plan.md` 第 1.2 节。

#### 后果

不增加对象存储 / CDN 产品费用；镜像仓库需要单独的服务器或数据盘（不放官网服务器），公网流量按量计费。

---

### ADR-0016: 控制台公网访问作为可选项（默认不开放）

**日期**: 2026-10-11  
**状态**: 接受（2026-10-11 负责人确定：首发前做，原则是“用户省心、尽快可用”），实现见下文  
**提出者**: [cc]

#### 决定（2026-10-11 修订，取代下方“原方案”）

用户唯一需要手动做的事，是在域名服务商那里加一条解析记录，其余全部自动完成。

**用户流程**

1. Skill 询问是否开放公网访问控制台，默认不开放。用户选择开放时，先讲清风险：拿到密码就等于拿到服务器的 root 权限，因为控制台能部署任意容器。
2. 用户只填一个域名，例如 `panel.example.com`。
3. 自动验证域名（`acornfox public-console enable DOMAIN`）：
   - 服务端取本机公网 IP：先查云厂商元数据，依次是阿里云 `100.100.100.200/latest/meta-data/eipv4`、`public-ipv4`，腾讯云 `metadata.tencentyun.com/latest/meta-data/public-ipv4`，火山引擎 `100.96.0.96/latest/eip_address`；都取不到再用国内可达的公共接口。IPv4、IPv6 都取。
   - 命令行（用户电脑）通过公共 DNS 查询域名的 A/AAAA 记录，国内用 223.5.5.5、119.29.29.29，海外用 1.1.1.1、8.8.8.8，判断是否指向本机。
   - 未指向时，输出“请在域名后台添加 A 记录：主机记录 panel，记录值 <IP>”，然后每 15 秒重查一次。总等待时间由 `--wait` 指定，默认 10 分钟；按 Ctrl+C 中断后重跑即可继续。
   - 已指向时做一次 HTTP 实测：服务端临时在 80 端口提供一个随机令牌（Caddy 里一个非 `af-` 前缀的临时服务器 `acornfox-verify`，30 分钟后失效），命令行用域名去取。取到令牌，才证明域名确实通到本机；取到别的内容说明经过了 CDN、代理，或者指向了别的服务器。
4. 验证通过后由服务端开通：
   - 生成约 138 位熵的随机密码（24 位，字符集 55 个），配置里只存 SHA-256；密码随机且熵足够高，不需要慢哈希。
   - 把域名加入 Caddy 的 `af-domains` HTTPS 服务器，Caddy 自动申请证书。
   - 命令行把密码写进用户电脑上的 0600 文件，只显示这一次，然后等待 HTTPS 就绪，最后给出能直接打开的 https 地址。
5. 常见卡点给出直白的诊断，代码在 `internal/publicconsole`：
   - `dns_unresolved`：域名未解析。
   - `dns_mismatch`：解析到了别处。
   - `port_closed` / `port_unreachable`：80 或 443 不通，提示去云厂商安全组放行。
   - `icp_blocked`：识别拦截页特征，提示“该域名未备案，国内服务器无法使用”。
   - `wrong_target`：经过 CDN 或代理。
   - `cert_pending` / `cert_failed`：证书在申请或申请失败，附常见原因。
   - `dns_error`：DNS 服务器都不可达。
6. 安全底线：
   - 登录由网关自己实现表单登录，不用 Basic 认证。
   - 失败限速：同一 IP 连续失败 5 次后锁定 1 分钟，之后每次加倍，最长 1 小时；全局 10 分钟内失败超过 50 次，暂停所有登录 10 分钟。
   - 会话沿用原生控制台的会话与 CSRF，Cookie 设为 Secure、HttpOnly、SameSite=Strict；写请求要求 Origin 与域名完全一致，并加 HSTS。
   - 网关只接受自己签发的会话。关闭时删除配置、撤销这些会话、移除 Caddy 路由，重新开启后旧会话全部失效。
   - 配置存在数据目录（`/var/lib/acornfox/public-console.json`，0600），升级不动数据目录，配置自然保留。
7. 开启、关闭、查看都有独立命令，风格与 `domain add`、`target add` 一致：
   - `acornfox public-console enable DOMAIN [--wait 10m] [--reset-password]`、`disable`、`status`。
   - 加 `--local` 在服务器本机经 `/run/acornfox/api.sock` 执行。`install.sh --public-console DOMAIN` 就是在安装最后调用这一条。
   - Skill 可以在任何时候帮用户开启。

**结构**

- 网关并入 `acornfox server`：新监听 `127.0.0.1:18801`（`-public-console-listen`，只允许回环地址）。Caddy 反代到这里，网关在进程内转交原生控制台处理。可信 API 仍只走 Unix socket，原生控制台 18800 不变。
- Caddy 路由：给 `Router` 包一层，把控制台域名作为“只有域名、没有端口”的路由并入 `af-domains`，路由带 `@id: af-route-_public-console`。调和器只新增一个 `RefreshRoutes`，先 ping 执行器再同步路由，这样没有应用时也能加上控制台路由。开启期间服务端每 30 秒调用一次，Caddy 重启后丢失的路由会自动补上。
- 开通相关的 API 只在可信 socket 上：`GET /v1/public-console`，`POST /v1/public-console/verify`、`/enable`，`DELETE /v1/public-console`。

**首发不做**

- 由我们分配 `xxx.acornfox.com` 子域名。这涉及备案主体和合规责任，另行评估。
- 账号体系与二次验证。

**与第 9 项、旧网关的关系**

- 张家口测试机的 `panel.acornfox.com`（ADR-0009）改用本功能开通：先停掉 `acornfox-public-console` 服务，并删除 Caddyfile 里的 `public-console` 站点块，因为它独占 443，与 `af-domains` 冲突；然后执行 `acornfox public-console enable panel.acornfox.com`。
- 首发后是否保留这个入口，仍由第 9 项决定。
- `acornfox/cmd/acornfox-public-console/` 与 `scripts/ops/public-console/` 被本功能取代。它们目前未提交，测试机还在使用，所以这次不删，等测试机迁移后再删除。

#### 已决定（2026-10-11，负责人确认）

实现后提出的三个待确认事项，负责人全部同意：

1. **只用密码登录，不设用户名**。忘记密码时用 `acornfox public-console enable DOMAIN --reset-password` 重新生成，旧密码和旧会话随之失效。
2. **密码交付**：密码写入用户电脑上仅本人可读（0600）的文件，只显示这一次。Skill 不读取这个文件，也不在对话里复述密码，由用户自己打开后存进密码管理器。
3. **测试机迁移与旧网关删除**：张家口测试机的 `panel.acornfox.com` 迁移到本功能，步骤见上一节，需要先停掉旧网关。迁移完成后删除 `acornfox/cmd/acornfox-public-console/` 和 `scripts/ops/public-console/`。迁移涉及测试机，需负责人另行批准后执行，删除放在迁移之后，见 `current-milestone.md` 第 12 项的待办。
   - 2026-10-11 [cc] 已完成：原测试机已被释放，新测试机没有旧网关，直接用本功能开通 `panel.acornfox.com`；两个旧目录已删除。真实环境验证见 `evidence/n7-acceptance-2026-10-11.md`。

#### 原方案（2026-10-11 第一版，已被上面的决定取代）

负责人决定在 Skill 里加一个“是否开放公网访问控制台”的选项，默认不开放。调研现状：

- 已发布的产品只支持本机访问：控制台监听 `127.0.0.1:18800`，`acornfox open` 经 SSH 隧道打开（N3）。
- ADR-0009 的公网入口是张家口测试机的运维特例，不能直接给用户用：
  - 网关 `cmd/acornfox-public-console` 把域名 `panel.acornfox.com`、Origin 和各个 socket 路径都写成常量，换域名要改代码重新编译，而且没有测试。
  - `build-release.sh` 不构建网关，`install.sh` / `upgrade.sh` 没有相关参数，Skill 也没有提到。
  - Caddy 配置靠手工合并。`scripts/ops/public-console/Caddyfile.example` 里写的是 `origins *`，`install.sh` 注释写明这会让管理接口拒绝所有请求，示例与产品的 Caddyfile 不一致。
  - 认证只有 Caddy Basic 认证（bcrypt），没有失败次数限制；浏览器会缓存凭据，控制台里退出也清不掉。

因此 Skill 现在没有可用的参数可以照着配置，这次只记录方案，不改 Skill。

#### 方案（第一版，已取代）

1. **网关可配置并补测试**：把 `acornfox-public-console` 改为 `acornfox public-console` 子命令，域名由参数传入，Origin 由域名推出；补充单元测试，覆盖认证标记、Host、Origin、令牌接口 404、Cookie 的 Secure 属性。改动文件：`acornfox/cmd/acornfox/`，原 `cmd/acornfox-public-console/` 删除或迁入。随主程序一起发布，不增加单独的发行附件。
2. **安装参数**：`install.sh` 增加 `--public-console DOMAIN`（默认关闭）和 `--disable-public-console`：
   - 安装 systemd 单元。
   - 生成至少 24 位随机密码，保存为 0600 文件，只显示一次，与管理员令牌的处理方式一致；Caddyfile 里只写 `caddy hash-password` 生成的哈希。
   - 在保留现有 `admin … { origins caddy }` 全局块的前提下追加站点块，再 reload。
   - `upgrade.sh` 保留该站点块，并重启网关。
3. **Skill**：在 `skills/acornfox/SKILL.md` 增加“控制台公网访问（可选）”一节：
   - 默认不开放，用户主动要求时才询问。
   - 先讲风险：拿到密码就等于拿到整台服务器的部署权限。
   - 核对前置条件：域名 A 记录已指向服务器，安全组已放行 80/443，中国大陆服务器的域名须已 ICP 备案，HTTPS 由 Caddy 自动申请。
   - 然后执行 `install.sh --public-console DOMAIN`；不在对话里复述密码，并说明如何关闭。
4. **文档**：更新 README、官网和本 ADR；ADR-0009 的测试入口改为按新方式部署，或者按第 9 项的决定下线。

#### 风险

- 控制台能部署任意容器，相当于服务器的 root 权限，公网暴露后只靠一个密码保护；Caddy 核心不带限速，需要接受这一点，或另外加限速。
- `persist_config off` 下 reload Caddy 后，动态添加的 `af-*` 路由要等调和器重新同步，实现时需要实测应用访问是否会短暂中断。
- 证书申请失败（DNS 未生效、未备案、80 端口不通）时要给出明确诊断，不能让入口静默不可用。

#### 当前表述

官网写作“控制台默认只在服务器本机监听，`acornfox open` 经 SSH 隧道打开”，与已发布的行为一致，实现公网选项后依然成立。

---

## 如何使用本文档

1. **做重要决策前**: 先在此文档提议,征求其他 Agent 意见
2. **实施中发现问题**: 记录遇到的困难和解决方案
3. **回顾时**: 检查决策后果是否符合预期,必要时废弃并提出新方案

**重要决策包括**:
- 架构选择(存储方案、通信机制)
- 安全策略(权限模型、认证方式)
- 用户交互(API 设计、CLI 命令结构)
- 性能折衷(实时性 vs 资源消耗)

**不需要记录**:
- 实现细节(变量命名、函数拆分)
- 临时决定(测试数据、调试方法)


### ADR-0017: 保留最近一次失败部署的镜像

日期：2026-10-11 [cc]。状态：已采用。

**背景**：迁移计划第 3 节第 5 条约定“失败构建的镜像自动清理”。测试机实测中，诊断卡的“添加 PostgreSQL 并重新部署”需要重新部署刚刚失败的版本（它在启动阶段因缺少 `DATABASE_URL` 失败，镜像已经构建好），但镜像在失败后立即被清理，重新部署去公网拉 `sha256:` 镜像而失败。

**决定**：
- 清理镜像时，除上线版本和最近 3 个历史版本外，再保留**最新一次部署**的镜像，条件是它失败且已经构建出镜像。更早的失败镜像照常清理；有了更新的部署后，这个失败镜像也会被清理。实现在 `state.KeptImageDeployments`。
- 添加附加服务时，如果最新一次部署失败且有镜像，就重新部署这个镜像；否则沿用原来的“重新部署上线版本”（`apiserver.redeployForAddon`）。这样从未上线过的应用也能一键修好，已有上线版本的应用部署的是用户刚提交的版本，而不是旧版本。

**代价**：每个应用最多多占一个镜像的磁盘。

---

最后更新: 2026-10-11 by [cc]
