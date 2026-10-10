# N7.1 控制台重做：构建测试与静态核对

[cc]，执行于 2026-10-11（macOS arm64，开发者 Mac）。对应 `current-milestone.md` N7 第 1 项。

## 1. 构建与测试（在 `acornfox/` 下）

| 命令 | 结果 |
|---|---|
| `go build ./...` | 通过 |
| `go vet ./...` | 通过 |
| `go test ./...` | 除 `internal/runner` 外全部通过，包括 `internal/console`、`cmd/acornfox`、`internal/apiserver`、`internal/caddyroute` |
| `node --test internal/console/addons_test.cjs internal/console/observations_test.cjs` | 9/9 通过 |

`internal/runner` 有 17 个 socket 往返测试报 `runner: unavailable`，这是 AGENTS.md 已写明的 macOS 已知限制（`internal/peer` 的对端凭据校验只在 Linux 上实现），与本次控制台改动无关；以 Linux 开发机结果为准。`TMPDIR=/tmp go test ./...` 这种写法在本次会话被权限拒绝，改用普通的 `go test ./...`；`cmd/acornfox` 与 `internal/caddyroute` 照样通过。

## 2. 本机启动与截图：未完成

已用 `go build -o /tmp/afpv/acornfox ./cmd/acornfox` 编出本地二进制。计划只用 `/tmp` 下的测试数据和 socket 启动 `acornfox server -console-listen 127.0.0.1:18801`，不接任何云上资源，再用 `POST /v1/console/tokens` 和 `/console/login?t=` 登录后截图。启动命令在本次会话被权限拒绝，检查本机有没有无头浏览器的命令也被拒绝了，所以**没有截图**，也没有用 curl 实测。`docs/evidence/console-redesign-2026-10-10/` 目录没有创建。

## 3. 静态核对（对照 `brand.md`、`console-design.md`）

| 项 | 结论 |
|---|---|
| 配色 | `app.css` 的浅色变量与 brand.md 色表逐项一致（ink、brand、brand-text、brand-soft、surface、surface-muted、line、ink-muted、track-off）；深色变量与色表深色列一致；`--on-brand` 为墨色，符合“运行青上的文字用墨色”。深色下的警告色与故障色提亮了（`#E8A93A` / `#F06A5C`），brand.md 没规定深色值，属于合理的适配 |
| 字体 | `@font-face` 引用 `fonts/` 下 5 个 IBM Plex woff2 文件，全部存在；目录里附 `OFL.txt` |
| 标志 | `index.html` 内联 SVG：轨道路径与规范一致；三个圆点的半径 3.5/5/6.5、圆心 x 19.5/35.3/54.2 与规范一致；开关头按 evenodd 镂空。favicon `brand/favicon.svg` 存在 |
| 结构 | 四个页面（我的应用、应用中心、服务器、设置），加上应用详情的六个标签（概览、日志、版本记录、配置、数据库、域名），都与 console-design.md 一致；停止确认框默认焦点在“取消” |
| 安全约束 | 没有外部资源，没有内联脚本、`<style>` 或 `style=""`，没有 `innerHTML`（`internal/console` 测试覆盖）；JS 只通过 CSSOM 设置 `style.width`，不违反 CSP `style-src 'self'` |
| 资源 404 | 静态服务按路径直接读取嵌入的文件系统，`fonts/`、`brand/` 子目录可以访问；`.woff2`、`.svg` 的 Content-Type 由 Go 内置的 MIME 表识别 |

注意：`serveStatic` 遇到不存在的路径会回退到 `index.html` 并返回 200，所以资源缺失在浏览器里不会显示成 404，只会表现为字体或图标没有生效。本次已核对所有引用的文件都存在。

## 4. 修改

本次没有改代码；静态核对没有发现必须修的问题。

## 5. 待人工确认

1. 在本机或测试机启动控制台，对主要页面截图（桌面与手机宽度、深浅色），确认没有控制台报错和布局错乱。这一项和里程碑第 4 项（测试机实机检查）可以合并做。
2. 在 Linux 开发机跑一遍 `go test ./...`，确认 `internal/runner` 通过。

## 6. 后续安排

2026-10-11 [cc]：负责人决定，以上两项不在 Mac 本机做，并入 `current-milestone.md` 第 4 项（张家口测试机实机检查），在测试机上一起完成。
