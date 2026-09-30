# N3 实现契约（开发用）

上层依据：迁移清单第 3.5 节（默认 SSH）、第 3.8 节（控制台界面规范）、第 5 节 N3 行；N1/N2 契约见 `n1-contract.md`、`n2-contract.md`。代码契约：`internal/state/console_types.go`、`internal/client/api.go`（N3 段）、`internal/caddyroute/api.go`（Domains、HTTPSConfig）。

## 0. 完成标准

1. 用户电脑上 `acornfox open` 一条命令打开控制台，不需要输入密码；Ctrl+C 关闭隧道。
2. 控制台按设计稿推荐方案实现（工作台 + “需要处理”提醒条），显示真实数据：应用、状态、网址、版本历史、诊断（一键复制给 AI）、日志、环境变量键名、数据卷、域名、主机资源；能停止 / 启动 / 回退，危险操作需要确认。
3. 服务器上 `127.0.0.1:18800` 不再能被未登录的请求调用（本地其他用户也不行）；无认证 API 只在 Unix socket 上。
4. `acornfox domain add example.com`：Caddy 为该域名提供 HTTPS（自动证书）；证书迟迟签不下来时给出诊断，说明 DNS 与备案要求。开发机上用 Caddy 内部 CA 验证流程。

## 1. 两个监听入口（`acornfox server`）

| 入口 | 默认 | 认证 | 提供 |
| --- | --- | --- | --- |
| 可信入口 | `-listen unix:/run/acornfox/api.sock -listen-group acornfox-users` | 靠 socket 组权限 | 完整 `/v1` API + `POST /v1/console/tokens` |
| 控制台入口 | `-console-listen 127.0.0.1:18800`（只允许回环地址） | 会话 Cookie + CSRF | 控制台静态文件、`/console/login`、与可信入口相同的 `/v1` API（`/v1/console/tokens` 除外） |

`-listen` 不再接受 TCP 地址（避免再出现无认证的 TCP API）；启动时发现则报错退出。

### 1.1 登录流程

1. CLI（经 SSH，走可信入口）`POST /v1/console/tokens` → `{"token":"<64 hex>","expires_in":60}`。
2. CLI 在本机选一个空闲端口 P，启动 `ssh -N -T -o BatchMode=yes -o ExitOnForwardFailure=yes -L 127.0.0.1:P:127.0.0.1:18800 [-p][-i] <ssh>`，等本地端口可连通后打开浏览器 `http://127.0.0.1:P/console/login?t=<token>`。
3. 服务器 `GET /console/login?t=`：`RedeemConsoleToken` 成功 → 设置 Cookie `af_session=<secret>; HttpOnly; SameSite=Strict; Path=/`（不设 Secure，因为是 http://127.0.0.1），302 到 `/`（去掉令牌，避免留在地址栏和历史里）。失败 → 返回一个中文说明页：“登录链接已失效，请重新执行 acornfox open”。
4. 页面启动时 `GET /v1/console/session` → `{"csrf":"<token>","expires_at":...}`；之后所有非 GET 请求必须带请求头 `X-AcornFox-CSRF`，否则 403 `csrf_required`。
5. `POST /v1/console/logout` 撤销会话。会话闲置 8 小时、最长 24 小时过期；过期后 API 返回 401 `session_expired`，页面显示“会话已过期，请重新执行 acornfox open”。

### 1.2 控制台入口的防护

- **Host 校验**：只接受 `Host` 为 `127.0.0.1:<任意端口>`、`localhost:<任意端口>`、`[::1]:<任意端口>` 的请求（防 DNS 重绑定），否则 421。
- 响应头：`Content-Security-Policy: default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'`，`X-Content-Type-Options: nosniff`，`Referrer-Policy: no-referrer`，`Cache-Control: no-store`（API）。
- 静态文件来自 `internal/console`（`//go:embed`），不读磁盘。

## 2. 新增 API（两个入口都有，另注明除外）

| 方法与路径 | 说明 |
| --- | --- |
| `POST /v1/console/tokens` | 仅可信入口 |
| `GET /console/login?t=`、`GET /v1/console/session`、`POST /v1/console/logout` | 仅控制台入口 |
| `GET /v1/apps/{app}/deployments?limit=20` | 版本历史（新到旧），元素同部署视图 |
| `GET /v1/host` | `{"cpu_percent","memory_used","memory_total","disk_used","disk_total","load1","uptime_seconds"}`，取自 `internal/hostmetrics` 或 /proc 直接读取；失败返回 `{"available":false}` |
| `GET /v1/apps/{app}/domains`、`POST /v1/apps/{app}/domains {"name"}`、`DELETE /v1/apps/{app}/domains/{name}` | 域名；名称校验（小写、合法主机名、至少一个点、不是 IP、≤253），重复属于其他应用 → 409 `domain_taken`。添加时解析 DNS：A/AAAA 不含 `-public-host`（当它是 IP 时）→ 响应里附 `warnings:[{code:"dns_mismatch",...}]`，不阻止 |
| `GET /v1/apps/{app}` | 应用视图增加 `domains` |

## 3. 域名与 HTTPS（`caddyroute`、`reconcile`）

- `caddyroute.New(adminSocket, HTTPSConfig)`（新增参数；旧调用处一起改）。Sync 时，若任一路由有 Domains，维护共享服务器 `af-domains`：只 `listen [":<HTTPSPort>"]`，每个应用一条路由 `match:[{host:[domains...]}]` → `reverse_proxy` 到该应用上游；HTTP 监听与 308 跳转交给 Caddy 自动生成，避免应用的 host 路由抢先在 HTTP 返回内容。`Issuer=internal` 时加 `apps.tls.automation.policies:[{subjects:[所有域名], issuers:[{module:"internal"}]}]`；只增改固定 `@id: "af-tls-policy"` 的自有策略，已有数组元素用 PATCH 替换。无域名时删除 `af-domains` 与我们的策略。
- 为保证已备案域名能用 80/443：生产上 Caddy 以自己的 systemd 服务运行并有绑定低端口的能力（N5 安装负责）；开发机测试用 `-https-port 18443 -http-port 18080 -https-issuer internal`。
- `reconcile` 每轮（应用级）对每个域名做一次 TLS 探测：连接 `127.0.0.1:<HTTPSPort>`，SNI=域名，校验证书链（`Issuer=internal` 时使用 Caddy 本地 CA 根证书路径 `-https-ca-file`，否则用系统根证书）且证书覆盖该域名 → `ready`；否则保持 `pending`，超过 `DomainPendingBudget` → `failed`，诊断 `domain/cert_pending`：message “域名 X 的 HTTPS 证书尚未签发”，hint “确认域名 A 记录指向本服务器、80 与 443 端口已放行；中国大陆服务器的域名须已完成 ICP 备案，否则 80/443 会被拦截、证书无法签发。未备案时请继续使用 http://IP:端口”。状态变化才写库和事件。
- server 新增 flags：`-http-port 80 -https-port 443 -https-issuer "" -https-ca-file "" -acme-email ""`。

## 4. 控制台（`internal/console` 与 `web/console/`）

- 删除旧的 `web/`（React，对接已删除的旧 API），新建 `acornfox/internal/console/`：`embed.go`（`//go:embed static` → `FS fs.FS`）与 `static/index.html`、`static/app.js`、`static/app.css`、`static/icons.svg`（可选）。**不引入任何构建工具或第三方库**；原生 ES2020，模块化写在一个或少数几个 JS 文件里。
- 视觉与交互以 `acornfox/prototype/ui-workbench/index.html` 的推荐方案（R）为准：桌面应用图标（首字母 + 按名称哈希的固定配色，带状态点：绿 运行、黄 部署中（缓慢闪烁）、红 失败 / 崩溃、灰 已停止）；“需要处理”提醒条（最多 3 条：最新部署失败、容器未运行但期望运行、域名证书失败；每条“查看”“复制给 AI”）；一行灰字状态；底部 Dock（服务器、让 AI 部署、设置）；点击图标打开应用窗口。浅色 / 深色跟随系统并可切换。
- 应用窗口：网址（可点）、状态、当前版本（第 N 版）、诊断卡片（有失败时置顶）、版本历史（可回退到上一版）、最近 100 行日志（手动刷新）、环境变量键名（密钥显示“已设置”）、数据卷、域名（状态 + 诊断）、停止 / 启动（停止需要确认对话框）。
- “复制给 AI”复制的文本：`请根据以下 AcornFox 部署诊断修复项目，然后重新执行 acornfox deploy：\n` + 诊断 JSON（stage、code、message、log_excerpt、hint、app、deployment_id）。
- “让 AI 部署”窗口：说明在 AI 工作台说“帮我部署”，以及手动命令 `acornfox deploy`；（Skill 安装在 N6）。
- 空状态：没有应用时显示引导。连接中断 / 会话过期 / 服务器错误有明确提示。
- 数据刷新：每 3 秒轮询 `GET /v1/apps` 与 `GET /v1/host`；打开的窗口轮询其详情。页面不可见时暂停。
- 所有用户数据用 `textContent` 或属性设置，不用 `innerHTML` 拼接数据；可键盘操作（Tab 顺序、Enter/Space 打开、Esc 关闭窗口），按钮有 `aria-label`。

## 5. CLI（`internal/cli`、`internal/client`）

- `acornfox open [--no-browser] [--port N]`：流程见 1.1；`url` 模式（直连开发用）直接用该 URL 的主机端口，不建隧道。打开浏览器：macOS `open`、Windows `rundll32 url.dll,FileProtocolHandler`、Linux `xdg-open`；失败或 `--no-browser` 时打印链接。保持运行直到 Ctrl+C 或 ssh 退出；`--json` 时打印 `{"ok":true,"url":"..."}` 后继续保持。转发被禁止（ssh 输出 `administratively prohibited` / `port forwarding is disabled`）→ `connect/forwarding_disabled`，hint：服务器 sshd 需要 `AllowTcpForwarding yes`。
- `acornfox domain add NAME` / `domain remove NAME` / `domain list`：add 输出里总是附一句：“中国大陆服务器的域名须已完成 ICP 备案，否则无法通过 80/443 访问”；有 `dns_mismatch` 警告时一并打印。

## 6. 验收（开发机 + Mac）

1. Mac 上 `acornfox open`：浏览器打开控制台，无需密码；地址栏不含令牌；同一登录链接第二次打开无效。
2. 开发机上 `curl 127.0.0.1:18800/v1/apps` 返回 401；带伪造 Host 的请求 421；无 CSRF 头的 POST 403。
3. 控制台：部署一个正常应用、一个构建失败的应用、一个崩溃的应用后，桌面显示 3 个图标与 2 条提醒；“复制给 AI”内容正确；停止（确认后）→ 图标变灰；回退可用；密钥不出现在页面与网络响应中。无头 Chrome 截图（桌面、提醒条、应用窗口、浅色）存档后删除。
4. 域名：`domain add notes.acornfox.test`（Issuer=internal，端口 18443），`curl --resolve notes.acornfox.test:18443:127.0.0.1 --cacert <caddy 根证书> https://notes.acornfox.test:18443/` 返回应用内容；状态变为 ready。把 CA 文件参数去掉（模拟证书签不下来）超过预算时间（测试时可调小）→ `domain/cert_pending` 诊断。
5. 全部包 `go test -race` 通过；六个平台编译通过。
