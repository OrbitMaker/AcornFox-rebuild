# N7 首发收尾：交给本地 Claude Code 的任务

日期：2026-10-10。布置人：负责人（经 Claude 云端会话整理）。执行人：本地 Claude Code（[cc]）。
负责人已授权：直接按本文执行，不必逐项再问；阿里云操作可用主账号 CLI 配置。遇到下面“停下来问”的情况才问。

开始前先读：`AGENTS.md`、`docs/current-milestone.md`（N7 一节）、`docs/active-tasks.md`、`docs/console-design.md`、`docs/brand.md`。
按 `AGENTS.md` 登记要改的文件；提交信息用 `[cc]` 开头。

## 背景

2026-10-10 云端会话已改好、但**未提交**的内容：
- 控制台重做：`acornfox/internal/console/static/`（新增 `fonts/`、`brand/`）。
- 官网重做：`website/`（新增 `assets/`、图标、`site.webmanifest`）。
- 文档：路线图第 6.3、9 节，`docs/brand.md`、`docs/console-design.md`、`docs/tech-decisions.md`（ADR-0014、0015）、`docs/current-milestone.md`、`docs/active-tasks.md`、`docs/licenses/THIRD_PARTY_NOTICES.md`，以及 `docs-private/` 下的应用中心规划与调研（不进仓库）。
- 云端已验证：控制台 9 项 node 测试、控制台包 Go 测试通过；用模拟接口在 Chromium 里看过所有页面（桌面 / 手机、深浅色），无报错、无横向溢出、空闲轮询不改动页面。**未做：整个模块的 Go 构建与测试、真实服务器实测。**

## 任务（按顺序）

1. **检查与提交改动**
   - `git status` 看清改动；`.cache/claude-sync/repo.tgz` 是云端会话留下的临时包，删除它。
   - 在 `acornfox/` 执行 `go build ./...`、`go vet ./...`、`TMPDIR=/tmp go test ./...`；控制台另跑 `node --test internal/console/*.cjs`。失败就修，修不了停下来问。
   - 用生成工具重新生成 `docs/licenses/licenses-manifest.json`，把 `IBM Plex`（OFL-1.1，控制台与官网自带的字体）纳入；若工具不支持字体条目，保留 `THIRD_PARTY_NOTICES.md` 里手写的一节并在提交说明里写明。
   - 分几次提交：文档一次、控制台一次、官网一次。

2. **修两个小问题**
   - `acornfox stop` 在容器实际停止前就打印“已停止”：改为等到观测状态变为停止（或超时给出明确提示）再打印。
   - `scripts/install/upgrade.sh` 摘要里打印了原始颜色转义码：修正。
   - 各自补测试或说明验证方式，单独提交。

3. **README 换新品牌**：标志改用 `website/assets/brand/lockup-horizontal.svg`（深色背景用 `-dark`），加一句口号“一拨即开”；其余内容不动。

4. **测试机实测新控制台**
   - 测试机信息见 `ops-private/test-environment.md`、`ops-private/cloud-server-operations.md`。张家口抢占式实例若已释放，用主账号新建一台同规格（2 核 4G、Ubuntu 24.04、抢占式），用完释放；记录实例 ID 与费用到 `ops-private/`。
   - 构建 Linux 版本装到测试机（或打 rc 标签走升级脚本），部署 3 个应用：一个正常的 Dockerfile 项目加 PostgreSQL、一个 nginx 镜像、一个启动即退出且日志里有 `DATABASE_URL is not set` 的失败应用。
   - 用 `acornfox open` 打开控制台，逐项检查并截图（桌面 1440×900、手机 390×844、深浅色）：首页开关启停（停止要确认、默认焦点在“取消”）、失败应用诊断卡和“添加 PostgreSQL 并重新部署”按钮、数据库标签开关添加 / 关闭（关闭时可选删除数据）、日志跟随与暂停、版本记录与回退到上一版、服务器页、设置页切换深浅色、“让 AI 帮忙”。
   - 发现问题就修，结果和截图写到 `docs/evidence/n7-console-2026-10-XX.md`。

5. **发版**：版本号 `v0.3.0`。打标签 → `scripts/build-release.sh` → GitHub Release → `scripts/publish-gitee.sh v0.3.0` 同步 Gitee。在测试机上用国内升级命令从 v0.2.3 升到 v0.3.0 验证一次。

6. **部署官网**：`website/` 提交后执行 `scripts/deploy-website.sh`（参数见 `ops-private/website.md`）。部署后用浏览器检查 https://acornfox.com 与 /install.html（桌面与手机），以及 /skill/SKILL.md 仍可下载。

7. **收尾**：更新 `docs/current-milestone.md` 的“首发前还需完成”表格各项状态，`docs/active-tasks.md` 删除完成的登记。

## 停下来问的情况

- 测试失败且原因涉及架构或数据库迁移；
- 需要付费超过一台抢占式测试机，或要动官网服务器以外的生产资源；
- 需要修改 DNS、安全组之外的账号级设置。

## 不在本次范围

应用中心与经营系统（N8，见 `docs-private/app-center-and-ops-system-plan.md`）；附加服务版本白名单；回退到指定版本。`panel.acornfox.com` 保留与否、开源公告、商标检索由负责人决定。

## 完成后回报

一段话：完成了哪几项、发布的版本号、官网是否已更新、实测发现并修复了什么、还有什么没做。
