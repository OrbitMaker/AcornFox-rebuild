# 从对应源码构建 AcornFox 发布包

构建入口是 `cmd/acornfox-release`。它从一个干净、detached HEAD 的 Git checkout 读取源码，分别核对工具链、运行时二进制和许可全文输入，再导出供安装器验证的六文件候选包。

构建成功不代表已经通过全新宿主、升级恢复或公网访问验收，也不会创建 GitHub Release。本指南构建 Linux amd64 包；安装步骤见 [install.md](install.md)。

## 工具和目录

在 Linux amd64 构建宿主上准备 Python 3.11 或更高版本、Git，以及：

| 工具 | 首版构建基线 |
| --- | --- |
| Go | `1.25.13`，与 `go.mod` 一致 |
| Node.js | `v22.22.0` Linux x64 |
| npm | 上述官方 Node.js 归档捆绑的 `10.9.4` |
| Git | 记录实际三段版本号和可执行文件 SHA-256 |
| BuildKit | `0.32.2` |
| RootlessKit | `3.1.0` |
| Caddy | `2.11.4` |
| `buildkit-runc` | 按 [runtime-build.md](runtime-build.md) 构建并校验 |

Node.js 和运行时上游输入的固定版本、地址与校验值见对应提交的 `internal/acornfoxrelease/product_build_inputs.go`、`release/runtime-inputs.json` 及运行时构建说明。不要直接混用不同发行版的 `buildkit-runc`；其本地库依赖及构建方法单独记录在 `runtime-build.md`。

以下示例在独立的 **root Bash** 终端执行，使用一个尚不存在的 `/root/acornfox-build` 目录。root 用于最后创建隔离网络命名空间；构建程序不会在 `/opt/acornfox` 安装服务。

先把已核对的 Go、Node.js 工具目录加入 PATH。务必指向实际使用的 Go 工具链，不能让一个旧 `go` 启动器在背后自动切换版本。

```bash
sudo -i
bash
set -euo pipefail
read -r -p '已安装的 Go 1.25.13 bin 绝对目录: ' go_bin
read -r -p '已安装的 Node.js v22.22.0 bin 绝对目录: ' node_bin
export PATH="$go_bin:$node_bin:/usr/sbin:/usr/bin:/sbin:/bin"
export GOTOOLCHAIN=local GOWORK=off GOENV=off
export GOOS=linux GOARCH=amd64 CGO_ENABLED=0
[ "$(go env GOVERSION)" = go1.25.13 ]
[ "$(node --version)" = v22.22.0 ]
[ "$(npm --version)" = 10.9.4 ]
git --version
python3 --version

build_root=/root/acornfox-build
[ ! -e "$build_root" ] && [ ! -L "$build_root" ]
install -d -m 0700 "$build_root"
for name in inputs cache npm-cache npm-seed scratch output tools tmp; do
  install -d -m 0700 "$build_root/$name"
done
install -d -m 0700 "$build_root/cache/go-cache" "$build_root/cache/go-mod-cache"
export GOCACHE="$build_root/cache/go-cache"
export GOMODCACHE="$build_root/cache/go-mod-cache"
export TMPDIR="$build_root/tmp"
```

## 固定对应的源码提交

从该版本发布说明取得完整的 40 位源码提交 SHA；标签名称本身不是这个校验值。下面以官方仓库为例。构建自己的修改时，应先提交到自己的分支，然后切换到该提交；`origin` 可使用自己的 HTTPS GitHub fork 地址，输入冻结脚本会记录实际地址，不会把本地构建当作官方发布。

```bash
read -r -p '发布说明中的完整源码提交 SHA: ' source_commit
[[ $source_commit =~ ^[0-9a-f]{40}$ ]]
source_root="$build_root/source"
# 普通 checkout 文件使用 0644，Git 可执行文件使用 0755。
umask 022
git clone --no-checkout https://github.com/EleJiuDeiChi/acornfox "$source_root"
git -C "$source_root" checkout --detach "$source_commit"
[ "$(git -C "$source_root" rev-parse HEAD)" = "$source_commit" ]
[ -z "$(git -C "$source_root" status --porcelain=v1 --untracked-files=all)" ]
```

不要在这份 checkout 中安装 `node_modules`、生成 `dist`、写缓存或保存构建输出。发布器会检查 Git 索引与提交树、全部文件摘要、权限及额外文件，而不只检查 `git status`。

## 准备运行时与许可输入

所有输入必须位于源码目录之外，各自使用独立目录。

按 [runtime-build.md](runtime-build.md) 取得并校验以下五个普通可执行文件，权限均为 `0755`。其中 `buildkit-runc` 使用该说明中的构建结果；不要从旧静态归档直接替换回来，也不要在目录内额外放 Buildx、归档或源码。

```text
/root/acornfox-build/inputs/runtime/
└── bin/
    ├── buildkitd
    ├── buildctl
    ├── buildkit-runc
    ├── rootlesskit
    └── caddy
```

许可输入是四个普通 `0644` 文件，保留 `docs/licenses/` 相对路径：

```bash
license_root="$build_root/inputs/licenses"
install -d -m 0755 "$license_root/docs/licenses"
for name in README.md THIRD_PARTY_NOTICES.md AGPL-3.0-only.txt licenses-manifest.json; do
  install -m 0644 "$source_root/docs/licenses/$name" "$license_root/docs/licenses/$name"
done
runtime_root="$build_root/inputs/runtime"
```

首版许可材料整理了 605 条组件全文记录。`licenses-manifest.json` 保存组件名称、版本、上游来源、完整 notice 及其 SHA-256；混合材料以对应全文摘要的 `LicenseRef-…` 记录，不能用 `NOASSERTION` 或一个许可名称替代全文。保持所构建提交中的时间戳、排序和原始字节；更改依赖时也要更新相应许可材料。候选构建器会据此生成 SBOM，并核对 AGPL 全文和许可输入。

## 联网填充依赖缓存

依赖下载在输入冻结与离线构建之前进行。Go 使用专用模块缓存；npm 在单独的临时目录安装，以避免污染冻结源码。

```bash
(cd "$source_root" && go mod download && go mod verify)
install -m 0644 "$source_root/web/package.json" "$build_root/npm-seed/package.json"
install -m 0644 "$source_root/web/package-lock.json" "$build_root/npm-seed/package-lock.json"
npm ci --prefix "$build_root/npm-seed" --cache "$build_root/npm-cache" \
  --ignore-scripts --no-audit --no-fund
npm cache verify --cache "$build_root/npm-cache"
(cd "$source_root" && go build -trimpath -buildvcs=false \
  -o "$build_root/tools/acornfox-release" ./cmd/acornfox-release)
```

不要在这之后清空或重建这些缓存目录。构建器会固定目录身份，并在整个构建阶段复核它们。缓存必须来自同一 Linux amd64 工具环境；缓存不完整时，离线构建会明确失败，应回到这一步补齐。

## 冻结输入

冻结脚本的五个位置参数依次为：源码目录、运行时目录、许可目录、尚不存在的控制输入输出目录、版本号；另外必须提供已经离线取得的官方 Pi v0.85.1 Linux x64 归档。脚本核对归档、固定资产清单和 `runtime_root/pi/**` 的逐文件摘要，不下载依赖，也不授予发布或安装权限。

```bash
control="$build_root/inputs/control-beta1"
pi_archive="$build_root/upstream/pi-linux-x64.tar.gz"
python3 "$source_root/scripts/acornfox/prepare-release-inputs.py" \
  "$source_root" "$runtime_root" "$license_root" "$control" 0.1.0-beta.1 \
  --pi-archive "$pi_archive"
```

脚本按 Linux amd64、禁用 CGO 的设置，对十一个产品命令执行 `go list -deps`，记录项目模块的完整 Go 包闭包。它还记录源码、运行时和许可树的文件摘要与权限，以及实际 Go、Git、Node.js 二进制和 npm JavaScript 入口的摘要。

控制目录包含 `source-policy.json`、`toolchain.json`、`runtime-inputs.json`、`license-inputs.json`、`decision.json` 和 `decision.sha256`。JSON 字段顺序与 Go 类型一致，并保留 Go 的 HTML、U+2028/U+2029 转义规则；不要用其他格式化器改写后继续使用旧摘要。这里的 `decision.sha256` 是自己刚冻结输入的本地依据，不是官方发布的 binding 摘要。

## 在断网环境构建候选包

`--cache`、`--npm-cache`、`--scratch` 及输出父目录必须预先存在、由当前用户所有且权限为 `0700`。最终 `--output` 目录必须不存在。实际构建使用 `GOPROXY=off`、`GOSUMDB=off`、`GOVCS=*:off`、`GOTOOLCHAIN=local`，前端使用 `npm ci --offline --ignore-scripts`。

```bash
read -r decision_sha256 < "$control/decision.sha256"
unshare --net -- "$build_root/tools/acornfox-release" build \
  --source "$source_root" \
  --decision "$control/decision.json" \
  --decision-sha256 "$decision_sha256" \
  --source-policy "$control/source-policy.json" \
  --toolchain "$control/toolchain.json" \
  --runtime-inputs "$control/runtime-inputs.json" \
  --license-inputs "$control/license-inputs.json" \
  --runtime-root "$runtime_root" \
  --license-root "$license_root" \
  --cache "$build_root/cache" \
  --npm-cache "$build_root/npm-cache" \
  --scratch "$build_root/scratch" \
  --output "$build_root/output/v0.1.0-beta.1"
```

成功后输出目录只有六个候选文件，格式见 [安装指南](install.md#2-下载并核对发布文件)。发布器已经将归档重新交给安装器校验，但这仍是未验收的候选。自己的工具版本、输入或源码变化会产生新的摘要，不能因此宣称与官方资产逐字节相同。

构建后继升级包时，必须使用符合升级兼容条件的下一版本源码与新的控制目录，并额外传入 `--predecessor-binding ABSOLUTE_PATH` 和 `--predecessor-sha256 TRUSTED_SHA256`；两个参数必须一起提供。保留前驱原始 binding 文件及独立可信摘要，不能仅凭版本号重建前驱身份。首次安装包与后继升级包的 binding 不同，应分别验收和保留。
