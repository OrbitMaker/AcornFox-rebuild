# 张家口测试机公网控制台验收

[codex] 2026-10-04，用户授权现有测试控制台公网访问。Claude Code 曾创建初稿；用户要求停止后已终止执行器，由主代理接管所有后续修正、部署及验收。本证据记录最终候选。

## 结果与范围

入口为 **https://panel.acornfox.com**，浏览器弹出管理员账号密码认证。当前服务器运行原 AcornFox `0.2.0-dev`，本次新增独立网关及 Caddy 静态入口。原可信 API、runner、数据库、业务应用未作修改。

云账号经 STS 实测确认（账号 ID 已脱敏，原文见 ops-private）。目标为国内云主机测试机，公网地址以 `203.0.113.10` 代称（可用区、实例 ID 已脱敏，原文见 ops-private）。80/443 ingress 原已开放，本轮未修改安全组。

新增 DNS A 记录 `panel.acornfox.com → 203.0.113.10`（RecordId、RequestId 已脱敏，原文见 ops-private）。服务器正常解析到目标 IPv4；保留全部原有 DNS 记录。

## 实现与候选

- 新增命令：`acornfox/cmd/acornfox-public-console/main.go`，仅标准库。
- 模板与运行说明：`scripts/ops/public-console/`。
- 服务：`acornfox-public-console.service`，运行账号 acornfox、主组 caddy、补充组 acornfox-users；已 enable，开机由 systemd 启动。
- 网关 socket：`/run/acornfox-public-console/gateway.sock`，0660 acornfox:caddy；目录 0750。
- Caddy 服务器：`public-console`，原调和器保留非 `af-*` 服务器；配置在 `/etc/caddy/Caddyfile`，0640 root:caddy。
- 最终 Linux 二进制 SHA-256：`375fe132f53581e69c60a2a1910eec74c15cdc8fa6518c5bb5cf6afaf846e6fd`，目标主机回读一致。
- 本地通过：`go vet ./cmd/acornfox-public-console`；`GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build ... ./cmd/acornfox-public-console`。

## 实机与公网证据

原生控制台仍监听 `127.0.0.1:18800`；公网监听由 Caddy 提供 80/443。gateway、acornfox、runner、Caddy 均 active。

| 检查 | 实际结果 |
| --- | --- |
| 公网 HTTPS，使用系统信任且不跳过校验 | 成功，curl ssl_verify_result=0 |
| 公网 HTTP | 308 跳转 HTTPS |
| 未认证首页 / 伪造认证标记 / 错误密码 | 401 |
| 正确认证、内部兑换会话、重定向后首页 | 200，标题 AcornFox 工作台，最终 URL 不含令牌 |
| 原生 session、apps、host metrics API | 均 200 |
| Cookie | Secure、HttpOnly、SameSite=Strict，Path=/，绑定公网域名 |
| 页面 JS / CSS | 200，分别 text/javascript、text/css，非 SPA fallback |
| Basic 已认证但无原生 Cookie 的 apps API | 401 |
| 同 Origin、缺失 CSRF 的 logout | 403 |
| 错误或缺失 Origin 的写请求 | 403 |
| 公网令牌签发接口 | 404 |
| 有效 Origin + CSRF 的 logout | 200，仅撤销本次验证会话 |
| 直连网关缺失标记 / 错误 Host | 401 / 400 |
| 最终候选错误公网端口 Host | 400，Cache-Control=no-store |
| 从保存 Caddyfile reload | exit 0，入口保留，重新认证及 API 验证通过 |

最终候选再次通过公网首页、session、apps、metrics、401、CSRF/Origin 403、token 404 和退出检查。网关首页与原生响应均为 no-store，Referrer-Policy=no-referrer。

应用列表仍是历史 8 个失败测试记录，无运行应用。本任务未进行业务部署，也没有宣称 N6 独立用户验收或浏览器绘制验收通过；页面、资源与登录后的 API 采用真实公网 HTTP 验证。

## 凭据、备份与回退

随机密码在本机用户配置目录的 0600 凭据文件，未写入仓库、执行器提示词或报告；服务器仅保存 bcrypt 哈希。原 Caddyfile 与运行 JSON 已备份到服务器上权限 0700 的目录（路径已脱敏，原文见 ops-private）。临时上传目录已清理。

回退先读取当前运行配置，保留任何后续新增应用路由，再恢复本次入口之前的 Caddy 配置；停用本次 gateway 服务，仅按本次 DNS 记录的 RecordId（见 ops-private）清理本次 DNS。现有其他 DNS、服务及数据不变。

参考：[Caddy basic_auth](https://caddyserver.com/docs/caddyfile/directives/basic_auth)、[reverse_proxy](https://caddyserver.com/docs/caddyfile/directives/reverse_proxy)、[servers name](https://caddyserver.com/docs/caddyfile/options#name)、[阿里云 AddDomainRecord](https://help.aliyun.com/zh/dns/api-alidns-2015-01-09-adddomainrecord)。
