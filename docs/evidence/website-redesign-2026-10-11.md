# N7.2 官网重做：核对、修复与静态验证

[cc]，2026-10-11，macOS 开发机。对应 `current-milestone.md` N7 第 2 项。未部署，未动任何服务器。

## 1. 现状

`website/` 在 2026-10-10 已按 `brand.md` 重写（未提交）：

- `index.html` 与 `install.html` 改用 `assets/site.css`、`assets/site.js`，去掉了内联样式和内联脚本。
- 新增 `assets/brand/`（标志各版本）、`assets/fonts/`（IBM Plex 字体与 `OFL.txt`）、网站图标、`site.webmanifest`。

本次在此基础上核对并修复，没有推翻重写。

## 2. 核对结果

| 项 | 结论 |
|---|---|
| 配色 | `site.css` 的浅色与深色变量和 brand.md 色表一致；主按钮墨色底；运行青上的文字用墨色 |
| 字体 | 与控制台是同一份文件：`diff -rq website/assets/fonts acornfox/internal/console/static/fonts` 无差异，`OFL.txt` 随附。中文落到系统黑体，符合规范。两处无法合并成一份：控制台用 `go:embed`，只能读取包目录内的文件；官网由 `deploy-website.sh` 打包 `website/` 目录 |
| 标志 | 页头、页脚内联 SVG 的几何与 brand.md 一致；favicon 为简化版（不画圆点） |
| 安装命令 | 6 条命令（服务端、命令行工具、升级，各分国内与海外）与 HEAD 版本、README 第 49–62、190–195 行一致；国内用 Gitee `raw/main`，海外用 GitHub `releases/latest/download`，符合 ADR-0011；`build-release.sh` 会把三个脚本附进发行版。选项表中的 `--version`、`--public-host`、`--registry-mirror`、`--china`、`--global`、`--skip-docker`、`--skip-caddy` 都能在 `install.sh` 的参数解析里找到。示例版本 `v0.2.3` 是已有标签（最新为 `v0.2.5`） |
| 外部资源 | 没有外部 CSS、JS、字体或图片。外链只有指向 GitHub、Gitee 的普通链接，以及 `og:image` 的绝对地址（社交分享卡片要求必须用绝对地址） |

## 3. 本次修复（`website/assets/site.css`）

1. 安装页每一步的卡片：序号原先用 `grid-row: 1 / span 40` 放置，会生成 40 个隐式行，每个行间距 8px，卡片底部因此多出约 300px 空白。改为在卡片左侧绝对定位序号；手机宽度下序号排在内容上方。
2. 首页“工作方式”的四步连线用了 `z-index: -1`，在带底色的 `.band.alt` 里会被背景盖住。给 `.flow` 加上 `position: relative; z-index: 0`。
3. 诊断示例的“诊断 · 第 4 版”原本用故障色写 13px 小字，对比度 4.40:1，低于 4.5:1。改为墨色文字加故障色圆点，与“圆点 + 文字”的状态标签规范一致。
4. 页头的 `color-mix()` 前面补一行纯色背景，不支持该函数的旧浏览器内核（部分国内 App 内置浏览器）照样有底色。
5. 带 `id` 的区块加 `scroll-margin-top`，点导航锚点跳转后标题不会被吸顶页头挡住。

## 4. 验证

`node /tmp/afcheck/check-website.cjs website`（脚本放在仓库外，没有提交），结果全部通过：

- 两个页面加载的 7 个资源、CSS 中的 5 个字体、manifest 中的 3 个图标都存在，`OFL.txt` 存在。
- 没有外链资源、`@import`、内联 style 或内联脚本；`site.js` 没有外部地址，语法能解析。
- `id` 没有重复，页内锚点和 `data-copy` 的目标都存在；所有 SVG 都有 `aria-hidden` 或替代文本；有 `lang` 和 `viewport`；主要标签开闭数量一致。
- 对比度（WCAG AA，≥ 4.5:1）11 组都达标：浅色正文 16.7，次要文字 5.6，链接 5.2，代码 5.0；深色次要文字 7.7，链接 10.0；命令框 15.0；运行青上的墨色 5.7。

键盘与焦点：全站有 `:focus-visible` 描边；复制按钮、地区切换、演示开关都是原生 `<button>`；演示开关带 `role="switch"` 和 `aria-checked`；用户开启“减少动态效果”时不自动播放演示，也不做动画。

## 5. 没有做的

- 截图与浏览器实机查看：本机没有 Chrome、Chromium、Edge 或 Playwright，无法无头截图；也没有启动本地服务器。官网的实机查看在 `current-milestone.md` 第 6 项（部署官网）完成后进行，该项已写明截图要求。第 4 项是测试机上的控制台检查，官网不在测试机上，所以不并入第 4 项。原先这里写的“并入第 4 项”有误，已于 2026-10-11 更正 [cc]。
- 部署：属于第 6 项，需要先提交 `website/`。

## 6. 2026-10-11 第二轮：负责人确认项 [cc]

| # | 决定 | 处理 |
|---|---|---|
| 1 | 首页 8 个应用的点名先不动 | 未改 |
| 2 | 删掉“90 秒”的说法 | 官网内只有两处：`install.html` 删掉“全新的国内云主机实测约 90 秒装好。”一句；`index.html` 首屏三项要点里的“90 秒装好一台全新的国内服务器”改为“国内可用：Gitee 镜像与国内软件源”（ADR-0011 已实现的能力，不含数字）。两页 meta 描述里本来就没有这个说法 |
| 2′ | 负责人后续决定：替换成的“国内可用”一条也删掉 | 2026-10-11 [cc] 已删除，首屏要点只剩“开源”“不中断”两条。`.facts` 是 `flex-wrap` 自动换行，没有按列写死，桌面与手机宽度都无需改 CSS；检查脚本全部通过 |
| 3 | 示例版本改为最新标签 | 按创建时间最新的标签是 `v0.2.5`。按版本号排序时 `v0.8.0-rc.*` 排在前面，但它们是更早的预发布标签。`install.html` 中的 `--version v0.2.3` 已改为 `v0.2.5`，官网其他地方没有版本号示例 |
| 4 | 控制台公网访问作为 Skill 选项 | 调研后结论是现有机制不足以安全地交给用户，Skill 未改，方案写入 ADR-0016 等待确认。官网的说法改为与已发布行为一致：“控制台默认只在服务器本机监听，`acornfox open` 经 SSH 隧道打开” |
| 5 | 清除来源元数据 | 12 个 SVG（官网 11 个，加上控制台的 `brand/favicon.svg`）去掉了 `<metadata>`（C2PA）和对应的命名空间声明，图形元素原样保留。5 个 PNG 删掉了 `caBX`（C2PA）辅助块，IDAT 像素数据不变。`favicon.ico` 不含这类数据。合计减少约 115 KB，例如 `favicon.svg` 从 8089 字节降到 315 字节 |

验证：
- `node /tmp/afcheck/check-website.cjs website` 全部通过。
- 复查确认 PNG 只剩 IHDR / IDAT / IEND，SVG 不再含 `c2pa` 或 `<metadata>`。
- `go -C acornfox test ./internal/console/` 通过（控制台 favicon 是嵌入资源，这次没有改 Go 代码）。
- 用 `grep` 复查官网，已没有“90 秒”、`v0.2.0–v0.2.4` 和“不对公网开放”的字样。

另发现：`assets/brand/lockup-horizontal.svg`、`lockup-horizontal-dark.svg`、`lockup-vertical.svg` 以及首页 `og:image` 用的 `lockup-horizontal-1200.png`，标志旁边的字都是“运维即服务”，不是 AcornFox 或“一拨即开”。这些文件的标题和替代文本也写着“运维即服务”。在社交平台分享官网链接时，卡片上会显示这几个字。是否属于有意为之需要负责人确认，本轮没有改动。

## 7. 标志组合改为 AcornFox（2026-10-11 [cc]）

负责人决定：lockup 上的文字由“运维即服务”改为“AcornFox”，其余按 brand.md 执行。

- 清单：全仓库只有 `website/assets/brand/` 下的 `lockup-horizontal.svg`、`lockup-horizontal-dark.svg`、`lockup-vertical.svg` 和 `lockup-horizontal-1200.png` 带这几个字（按文件名与内容核对）。控制台 `static/brand/` 只有 favicon，`docs/` 里没有标志文件。
- 做法：开关图形的路径原样保留。文字用仓库自带的 `website/assets/fonts/IBMPlexSans-Bold-Latin1.woff2` 转成路径，字距取字体 GPOS 表里的 kern（c-o −5、F-o −32、o-x −16）。布局沿用原 lockup 的文字区：横版 x 147–402.6、大写字母在 y=30 居中；竖版间距 24、宽度与原文字一致。尺寸参数写入了 brand.md。
- 尺寸：横版仍为 404×60；竖版高度由 128.16 变为 123.09，因为拉丁字母比汉字矮。分享图仍为 1200×178 RGBA、透明底。`og:image` 引用的文件名不变。
- 工具（都装在仓库外）：fontTools 4.66.1、brotli 1.2.0（解压 woff2、提取字形）、resvg-py 0.5.0（渲染 PNG），用 `pip install --target /tmp/aflogo-py` 安装；生成脚本是 `/tmp/aflogo/gen.py`。
- 被拒绝的命令：
  - `npm install --prefix /tmp/aflogo-tools opentype.js wawoff2 @resvg/resvg-js`，因此改用 pip。
  - `PYTHONPATH=… python3 …`，改为在脚本里设置 `sys.path`。
  - `cp /tmp/aflogo/out/… website/assets/brand/`，路径在工作目录之外，改为生成脚本直接输出到仓库目录。
- 验证：
  - 生成的文件不含 C2PA 等元数据，PNG 只有 IHDR / IDAT / IEND。
  - 官网已没有“运维即服务”字样。
  - 浅色、深色、竖版都渲染出来逐张查看过。
  - `check-website.cjs` 全部通过。
  - 控制台资源没有变动，所以未跑 Go 测试。
