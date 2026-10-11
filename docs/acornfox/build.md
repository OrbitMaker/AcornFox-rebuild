# 构建与发布

[cc] 2026-10-11 重写。本文说明怎样从源码构建 AcornFox、怎样发布一个新版本。服务器端依赖的 Docker 与 Caddy 从哪里来，见 [runtime-build.md](runtime-build.md)。

## 产物是什么

AcornFox 只有一个程序 `acornfox`，服务端（`acornfox server`、`acornfox runner`）和用户电脑上的 CLI 是同一个文件。网页控制台的页面、字体、图标通过 `go:embed` 编进程序（`acornfox/internal/console/static/`），没有单独的前端构建步骤。

程序纯 Go 编写，`CGO_ENABLED=0` 构建；SQLite 用的是纯 Go 实现 `modernc.org/sqlite`，不依赖系统库。

## 本地构建

需要 Go，版本与 `acornfox/go.mod` 中的 `go` 一行一致（目前是 1.25.13）。

    cd acornfox
    go build ./...
    go vet ./...
    TMPDIR=/tmp go test ./...           # macOS 需要 TMPDIR=/tmp，原因见 AGENTS.md
    node --test internal/console/*.cjs  # 控制台脚本的测试

`internal/runner` 的 socket 测试依赖 Linux 的对端凭据校验，只能在 Linux 上通过；发版前要在 Linux 上跑一次全量测试。

只想得到当前平台的程序：

    go build -o acornfox ./cmd/acornfox

## 发布产物

    scripts/build-release.sh v0.3.0

脚本在仓库根目录的 `dist/` 下生成：

| 文件 | 说明 |
| --- | --- |
| `acornfox_<os>_<arch>[.exe]` | linux、darwin、windows 各 amd64 与 arm64，共 6 个；`-trimpath -s -w`，版本号经 `-ldflags` 写入 `internal/cli.Version` |
| `SHA256SUMS` | 上面 6 个程序的 SHA-256，安装脚本下载后据此校验 |
| `install.sh`、`upgrade.sh`、`install-cli.sh` | 从 `scripts/install/` 原样复制 |
| `caddy_<版本>_linux_{amd64,arm64}.tar.gz`、`caddy_<版本>_checksums.txt`、`caddy_LICENSE` | 随附的 Caddy 官方安装包，见 [runtime-build.md](runtime-build.md) |

## 发布一个版本

按顺序执行。

1. **确认可以发版**：工作区干净，`main` 已推送到 GitHub；Linux 上 `go test ./...` 全部通过；需要实机验证的改动已在测试机验证。
2. **更新许可材料**（依赖、Caddy 版本或自带字体有变化时）：`python3 scripts/gen-licenses.py`，提交 `docs/licenses/` 的变化。
3. **打标签并推送**：

        git tag -a v0.3.0 -m "v0.3.0"
        git push origin-acornfox v0.3.0

4. **构建**：`scripts/build-release.sh v0.3.0`。
5. **GitHub Release**：上传 `dist/` 下全部文件。

        gh release create v0.3.0 dist/* --repo OrbitMaker/AcornFox-rebuild --title v0.3.0 --notes-file <说明文件>

6. **同步 Gitee**（中国大陆用户从这里下载，见 ADR-0011）：`scripts/publish-gitee.sh v0.3.0`。脚本推送 `main` 与标签，创建同名发行版并上传 `dist/` 下的文件。需要 Gitee 令牌：环境变量 `GITEE_TOKEN` 或文件 `~/.config/acornfox/gitee-token`。
7. **清理旧发行版**：`scripts/prune-releases.sh`，GitHub 与 Gitee 都只保留最新两个（Gitee 单仓库附件总量限 1GB）。git 标签保留。
8. **验证**：在一台已安装旧版本的服务器上执行升级，确认服务正常、应用没有中断；国内服务器走 Gitee 路径，境外服务器走 GitHub 路径。
9. **记录**：在 `docs/current-milestone.md` 的“发布记录”中写一行。

## 安装脚本怎样找到版本

`install.sh`、`upgrade.sh`、`install-cli.sh` 不指定 `--version` 时取最新发行版：中国大陆查 Gitee 的 `releases/latest`，其他地区查 GitHub。下载地址固定为 `<发行版>/acornfox_<os>_<arch>`，所以 `dist/` 中的文件名不能改。

## 官网

官网是 `website/` 下的静态页面，与程序版本无关，单独部署：先提交 `website/` 的修改，再运行 `scripts/deploy-website.sh`。服务器参数不写在仓库里。
