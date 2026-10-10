# 第 12 项：控制台公网访问（ADR-0016）实现与单元测试

[cc]，2026-10-11，macOS 开发机。没有在本机或任何云服务器上做真实开通，也没有动云上资源。真实环境验证见 `current-milestone.md` 第 4 项第 ③ 条。

## 1. 实现

| 部分 | 文件 | 内容 |
|---|---|---|
| 核心逻辑 | `acornfox/internal/publicconsole/`（新增） | `diag.go`：诊断码、中文提示、主机记录推算、域名规范化。`publicip.go`：先查云厂商元数据，依次是阿里云 eipv4 / public-ipv4、腾讯云、火山引擎 `100.96.0.96/latest/eip_address`，再查公共接口，IPv4、IPv6 都取。`dns.go`：直接向 223.5.5.5、119.29.29.29、1.1.1.1、8.8.8.8 查询。`probe.go`：HTTP 令牌实测与 HTTPS 检查，识别拦截页、拒绝连接、超时、连接重置、TLS 错误。`config.go`：0600 配置文件与密码（24 位，约 138 位熵，只存 SHA-256）。`limiter.go`：登录限速。`router.go`：Router 包装。`manager.go`：verify / enable / disable / status。`gateway.go`：表单登录、Origin 校验、HSTS、只接受自己签发的会话、Cookie 加 Secure |
| Caddy | `internal/caddyroute/caddy.go`、`api.go`、`verify.go`（新增） | `PublicPort=0` 表示只有域名、没有端口的路由，放进 `af-domains` 并带 `@id`；`Verifier` 在 80 端口提供临时验证服务器 `acornfox-verify`，`Sync` 不会删除它 |
| 调和器 | `internal/reconcile/reconcile.go` | 只新增 `RefreshRoutes`：先 ping 执行器再同步路由，没有应用时也能把控制台路由加上 |
| 状态库 | `internal/state/console_store.go` | 新增 `RevokeConsoleSessionDigest`，用于关闭时撤销网关签发的会话；没有改 Store 接口，没有加迁移 |
| API | `internal/apiserver/public_console.go`（新增）、`apiserver.go`、`domains.go` | 只在可信 socket 上提供 `GET/DELETE /v1/public-console`、`POST /v1/public-console/verify`、`/enable`；应用不能占用控制台的域名 |
| 服务端 | `cmd/acornfox/server_runner.go` | 新参数 `-public-console-listen`（默认 `127.0.0.1:18801`，只允许回环地址）；网关监听；启动时清理残留的验证服务器；开启期间每 30 秒补一次路由 |
| 客户端与命令 | `internal/client/api.go`、`client.go`，`internal/cli/public_console.go`（新增）、`cli.go` | `acornfox public-console enable 域名 [--wait 10m] [--reset-password] [--local]`、`disable`、`status`。`unix://` 地址用于 `--local`。密码写入用户电脑上的 0600 文件，JSON 输出里不含密码 |
| 安装 | `scripts/install/install.sh` | `--public-console 域名`：安装最后执行 `acornfox public-console enable 域名 --local --wait 10m`；失败不影响安装 |
| Skill | `skills/acornfox/SKILL.md`、`acornfox/internal/cli/skilldata/SKILL.md` | 新增“网页控制台与公网访问（可选）”一节：默认不开、先讲风险、诊断码对照表、不读取也不复述密码 |
| 官网 | `website/install.html`、`website/index.html` | 参数表补上 `--public-console`；首页补充“需要时可绑定自己的域名开启公网访问，自动 HTTPS、密码登录” |
| 文档 | `docs/tech-decisions.md` | ADR-0016 改为已接受，写入新流程，旧方案保留作记录 |

升级：配置在 `/var/lib/acornfox/public-console.json`，`upgrade.sh` 不动数据目录；新参数有默认值，systemd 单元不用改。

## 2. 测试（`go -C acornfox …`，三条命令分开执行）

- `go build ./...`：通过
- `go vet ./...`：通过
- `go test ./...`：只有 `internal/runner` 的 17 个 socket 测试失败（`runner: unavailable`，macOS 已知限制），其余全部通过

新增测试覆盖：

| 文件 | 覆盖 |
|---|---|
| `internal/publicconsole/check_test.go` | DNS：通过、一台服务器超时、未解析、解析到别处、多余的 AAAA、全部超时。HTTP：取到令牌、80 拒绝连接、80 超时、未备案拦截页、CDN/别的服务器、连接重置、本机解析不到。HTTPS：就绪、证书未签发、TLS 告警、443 拒绝、443 超时、拦截页。公网 IP：阿里云、火山引擎、内网与 CGNAT 地址排除、公共接口与 IPv6。主机记录与域名校验 |
| `internal/publicconsole/server_test.go` | Manager：非法域名、与应用域名冲突、未验证不能开通、验证过期、取不到公网 IP、开通后只存哈希、重复开通不换密码、关闭时撤销会话。网关：未登录跳转、令牌登录入口 404、跨站登录 403、Cookie 属性、HSTS、转发时 Host 改为回环地址、写请求要求 Origin、拒绝不是自己签发的会话、退出后失效、域名不符返回 421、关闭后返回 404。限速：5 次后锁定、只锁定该客户端、到期解锁、时长加倍且有上限、全局暂停。Router 包装：缺路由与旧路由都会触发同步。密码格式 |
| `internal/caddyroute/domain_only_test.go` | 只有域名的路由，以及验证服务器的设置、清除，确认 `Sync` 不会删除验证服务器 |
| `internal/apiserver/public_console_test.go` | 4 个接口、错误映射、应用不能占用控制台域名、控制台入口不提供管理接口 |
| `internal/client/public_console_wire_test.go` | 经 `unix://` 连接，4 个接口完整往返 |
| `internal/cli/public_console_test.go` | 等待后开通（DNS 晚生效，HTTPS 重试一次）；JSON 不泄露密码，密码文件为 0600；人可读输出给出解析指引且不重复刷屏；未解析、解析到别处、80 不通、未备案时不开通；`--local`、`status`、`disable`；参数校验 |

官网检查脚本 `node /tmp/afcheck/check-website.cjs website`：全部通过。

## 3. 被拒绝的命令

- `bash -n scripts/install/install.sh`（语法检查）：未执行，`install.sh` 的改动需要在测试机上实测确认。

## 4. 已知限制与待实测

- 验证服务器、自动 HTTPS 跳转、ACME 验证都共用 80 端口，这一点只在模拟的 Caddy 上测过，需要在真实 Caddy 2.8.4 上确认。
- `install.sh --public-console` 是在服务器本机做 HTTP 实测，经过云厂商网络回环，可能看不到未备案拦截。在用户电脑上执行 `enable` 的验证更准确。
- 未备案拦截页的识别依赖页面上的关键词（备案、ICP filing、beian 等），以测试机上的实际页面为准，必要时补充关键词。
- 测试机上的旧网关 `acornfox/cmd/acornfox-public-console/` 与 `scripts/ops/public-console/` 还在使用，而且没有提交，这次没有删除。
