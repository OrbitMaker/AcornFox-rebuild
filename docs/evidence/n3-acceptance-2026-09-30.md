# N3 开发机与 Mac 验收

日期：2026-09-30。结论：**通过 N3 开发机 + Mac 验收**。本次由当前 Codex 主会话直接实施与验收，独立 Codex 子代理审查最终差异，未调用 Claude Code。

本结论不包含 N5 干净安装／升级、真实公网 ACME、Windows 实机部署或 N6 独立用户首发验收。项目仍处于阶段 0。

## 候选与环境

- 分支：`acornfox-rebuild-20260929`；源码基线 `3669ccc0`，加本次经过验证的修复。
- Go 模块文件清单摘要：`7826b092ce6422fbf35d6b1dc7d90575ffb7e57230131db42ab686023a4ceff7`，清单包含模块文件与网页资源，排除参考原型。README 状态更新不改变构建输入。
- Linux amd64 实际运行二进制 SHA-256：`4c49d0f3db59421f7670c6d126f37c21b32923c892c80cf7b64af7d70f0071b1`。
- 开发机身份：`ubuntu-MS-7B89 / ubuntu`。Go `1.25.13`、Docker `29.1.3`；Go 构建与测试全部在开发机执行。
- 三个样本：`notes` 正常运行；`shop` 故意缺少构建依赖；`blog` 故意在启动后退出。截图中的两条故障提醒是验收样本。
- 控制台监听 `127.0.0.1:18800`；可信 API 为 Unix socket。开发机现有独立 Caddy、SQLite 与应用保留；本次临时 Caddy 使用另一份私有配置与空闲端口。

## 验收结果

| 检查 | 结果与证据 |
| --- | --- |
| Mac `acornfox open` | 实际经 SSH 打开系统默认浏览器；登录后地址栏无令牌。 |
| 单次登录与权限 | 初始 17 项 HTTP 检查、最终候选 11 项重点检查通过：无会话 401、伪造 Host 421、控制台不能签发令牌、一次性兑换、无／错误 CSRF 403、合法注销与注销后拒绝访问；Cookie 与安全响应头符合契约。 |
| 工作台与诊断 | 三个应用与两条提醒正确；Mac 系统剪贴板及最终候选无头 Chrome 实测得到含 app、deployment_id、stage、code、message、log_excerpt、hint 的诊断 JSON。 |
| 交互状态 | 停止确认的取消与执行、启动、版本回退通过；跨多轮轮询后键盘焦点、确认框焦点、日志滚动 817px 保持；深浅色页面已截图。 |
| 实际运行结果 | 最终候选停止后 Docker 确为停止，启动后恢复运行；控制台回退创建第 4 版，实际镜像恢复为原第 1 版镜像，IP 地址不变且可访问。提交型操作不会提前提示“已完成”。 |
| 密钥 | 写入测试密钥后，CLI、应用 API、页面不回显；向受管样本的实际 Docker 日志写入测试值后，日志 API 返回脱敏内容。 |
| HTTPS 正向 | 内部 CA 校验证书链与域名后取得应用内容；域名状态 ready；HTTP 返回 308，保留路径与查询参数。 |
| HTTPS 负向与恢复 | 开发机已经信任当前内部 CA，省略参数时仍为 ready；改用另一份有效测试 CA 后，严格验证失败，返回 domain/cert_pending、DNS／备案／IP 访问提示；IP 应用仍可用。恢复正确 CA 后回到 ready。没有修改宿主信任。 |
| 解绑 | 删除最后一个域名后，自有 af-domains、TLS 策略及 18080／18443 监听消失；IP 访问保留。重新绑定恢复正常。 |
| Go 与平台 | 全部包 `go test -race -p 2 ./...` 通过（20 个有测试的包）；Windows／macOS／Linux × amd64／arm64 六个平台编译通过。 |
| 真实 Caddy 回归 | 独立真实 Caddy + race 验证 HTTPS、HTTP 308、重复 Sync、解绑清理；原有保护外部服务器／策略的单元测试通过。 |
| 独立审查 | 最终候选未发现 P0／P1 阻断。 |

## 实测发现与修复

1. 应用窗口遮罩高于窗口，点击按钮反而关闭窗口：将应用遮罩设为 29，保持窗口 30、确认遮罩／对话框 70／71。
2. 域名应用路由同时监听 HTTP，抢在自动跳转前返回应用内容：只在 HTTPS 监听，由 Caddy 生成 HTTP 重定向。真实回归先复现 HTTP 200，再验证 308；依据 [Caddy 自动 HTTPS 文档](https://caddyserver.com/docs/automatic-https)。
3. 已有 TLS 策略使用 POST，同步时造成 duplicate ID，部署超过 5 分钟后失败：改用 PATCH 替换自有数组元素，真实重复 Sync 回归通过；依据 [Caddy API 文档](https://caddyserver.com/docs/api)。
4. 轮询删除并重建窗口，抢走键盘／确认框焦点、重置日志滚动和诊断展开：仅首次开窗聚焦，同视图恢复焦点、滚动与展开状态。
5. 操作提交即提示完成、更新中旧容器仍服务却显示未运行、复制失败仍提示已复制：提示按提交状态和实际运行观测显示，复制回退检查真实返回值。

## 证据与边界

本地证据目录：`Open Card/.codex-artifacts/acornfox-rebuild-n3-20260930/`。核心文件：`accepted-source-manifest.json`、`native-ui-checks.json`、`native-final-clipboard-check.json`、`remote-evidence/accepted-race.log`、`accepted-build-hashes.txt`、`accepted-caddy.log`、`final-auth-checks.json`、`rollback-checks.json`、`secret-log-checks.json`、`ca-negative-checks.json`、`domain-remove-checks.json`。四张无头 Chrome 截图位于 `headless-screenshots/`，另保留 Mac 实际操作截图。

本轮只验证一个目标与独立 Caddy。共用 Caddy 的非默认全局端口所有权、多目标控制台 Cookie 隔离和过期会话摘要定期清理留作后续；它们不作为本轮已通过能力。两账号安装权限和升级恢复仍属于 N5。

完成前关闭本任务浏览器与 SSH 隧道，回收临时 Chrome 配置、测试 Caddy 数据及任务构建缓存；保留已运行候选、原 SQLite、Caddy 数据和三个验收样本，方便后续复现。
