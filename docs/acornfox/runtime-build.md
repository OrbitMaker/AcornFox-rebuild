# 构建随包容器运行工具

当前 binding schema 2 候选只携带容器运行工具：BuildKit、RootlessKit、Caddy 和按下文构建的 runc；不携带 Pi、助手执行程序或助手 systemd 单元。固定版本和历史归档来源见 `release/runtime-inputs.json`，构建时应以当前容器工具清单为准。

历史 schema 1 包曾包含 Pi 0.85.1 的 218 文件树。`internal/pibundle/assets-v0.85.1-linux-x64.json` 与 arm64 清单保留用于验证已有安装及回退；它们不再是新包的运行依赖。不要为新候选下载或装配 `runtime_root/pi/**`。

`buildkitd`、`buildctl`、`rootlesskit`、`caddy` 保留官方归档原字节。**不要复制官方 BuildKit 归档中的静态 `buildkit-runc` 到本版输入目录。** 本版使用下面的动态构建，同样保留 seccomp 支持。构建身份、编译器和系统包版本、输入及输出摘要见 `release/acornfox-runc-build-v1.json`。

## runc 的可检查构建方法

以下命令在干净的 Ubuntu 24.04 amd64 构建机执行，需要 Go 1.25.13、GCC 13.3.0、binutils 2.42、Python 3、pkg-config 和 libc6-dev 2.39。对应 Ubuntu 包的完整版本列在上述构建收据中。使用 Go 官方工具链，先按官方校验值验证下载；`go version` 应为 `go version go1.25.13 linux/amd64`。

构建目录使用新空目录。libseccomp 开发包只解包到私有 sysroot，不替换宿主库。若软件源已轮换对应版本，应从 Ubuntu 官方包归档取得相同 deb 并核对以下摘要，不忽略版本差异。

```bash
set -euo pipefail
umask 077
build_root=$(mktemp -d)
cd "$build_root"
curl --fail --location https://codeload.github.com/opencontainers/runc/tar.gz/refs/tags/v1.4.3 -o runc.tar.gz
printf '%s  %s\n' e0a89f9e883ce93e740d14bb105b25c665f7d7beade4cfd0714fcafb38855d35 runc.tar.gz | sha256sum -c -
mkdir debs sysroot output go-cache go-mod-cache tmp home
cd debs
apt-get download libseccomp-dev=2.5.5-1ubuntu3.1 libseccomp2=2.5.5-1ubuntu3.1
printf '%s  %s\n' \
  26421f22f2150986735b79ece61d811400debab7fa505b08b731ec5a7917e45f libseccomp-dev_2.5.5-1ubuntu3.1_amd64.deb \
  33fc96f1e008d27c042a3db9bcd16f7f4d49e866f7a3141b758a799328dbdc3f libseccomp2_2.5.5-1ubuntu3.1_amd64.deb | sha256sum -c -
for deb in ./*.deb; do dpkg-deb -x "$deb" "$build_root/sysroot"; done
cd "$build_root"
tar -xzf runc.tar.gz
verified_go=$(command -v go)
test "$("$verified_go" version)" = 'go version go1.25.13 linux/amd64'
cd runc-1.4.3
env -i PATH="$(dirname "$verified_go"):/usr/bin:/bin" \
  HOME="$build_root/home" TMPDIR="$build_root/tmp" LANG=C LC_ALL=C TZ=UTC \
  GOMAXPROCS=2 GOENV=off GOWORK=off GOTOOLCHAIN=local CGO_ENABLED=1 \
  GOOS=linux GOARCH=amd64 GOPROXY=off GOSUMDB=off GOVCS='*:off' \
  GOCACHE="$build_root/go-cache" GOMODCACHE="$build_root/go-mod-cache" \
  CC=/usr/bin/gcc PKG_CONFIG=/usr/bin/pkg-config \
  PKG_CONFIG_LIBDIR="$build_root/sysroot/usr/lib/x86_64-linux-gnu/pkgconfig" \
  PKG_CONFIG_SYSROOT_DIR="$build_root/sysroot" \
  "$verified_go" build -p=2 -trimpath -buildmode=pie -mod=vendor -buildvcs=false \
  -tags 'seccomp urfave_cli_no_docs' \
  -ldflags '-s -w -buildid= -X main.gitCommit=bb14dabeb7185bb72c8c86735d090dcb20f36587 -X main.extraVersion=+acornfox.1' \
  -o "$build_root/output/buildkit-runc" .
chmod 0755 "$build_root/output/buildkit-runc"
"$build_root/output/buildkit-runc" --version
readelf -d "$build_root/output/buildkit-runc"
readelf -l "$build_root/output/buildkit-runc"
sha256sum "$build_root/output/buildkit-runc"
```

发布构建的输出摘要为 `5702b7a2f87e40a4f5cfae74984ef94e6dcb2840ee4ddb6a7accd8d47a4bce56`。版本输出包含 `1.4.3+acornfox.1`、`go1.25.13` 和 `libseccomp: 2.5.5`。动态依赖应为 `libseccomp.so.2`、`libc.so.6`，解释器为 `/lib64/ld-linux-x86-64.so.2`；不得携带私有 RPATH/RUNPATH。修改编译器、源码或库后输出摘要可能不同，须重新冻结运行工具输入并验证构建和容器行为。

## Linux arm64 runc 复现

ARM 的已完成构建事实记录在 `release/acornfox-runc-build-linux-arm64-v1.json`：Ubuntu 24.04 arm64 上使用 Go `1.25.13`、GCC `13.3.0` 和系统 `libseccomp-dev:arm64 2.5.5-1ubuntu3.1`，对官方 runc `v1.4.3` 源码（摘要 `e0a89f9e883ce93e740d14bb105b25c665f7d7beade4cfd0714fcafb38855d35`）原生构建两次，输出摘要均为 `6607030be180844bcf95fa857cef618fcedeffd54d69fe2f829d1e2c3faee3bf`。

复现必须在干净的原生 Ubuntu 24.04 arm64 主机执行：先校验 Go Linux arm64 归档摘要 `adad240fcb6bd180cf973b4b7c747baf4ec81d08b7d40ca35940ee4531971490` 与 runc 源码摘要；在新的私有工作目录解包二者，再以干净环境设置 `GOOS=linux GOARCH=arm64 CGO_ENABLED=1 GOPROXY=off GOSUMDB=off GOVCS='*:off'`。构建使用 `-p=2 -trimpath -buildmode=pie -mod=vendor -buildvcs=false`、tags `seccomp urfave_cli_no_docs`，以及收据中的 ldflags；对两次输出分别校验摘要、`runc --version`、AArch64 ELF、`libseccomp.so.2`/`libc.so.6` 和无 RPATH/RUNPATH。该 ARM 记录使用宿主系统的官方 arm64 开发包，不复制 amd64 私有 sysroot 方法。

这些模块证明了架构选择、官方运行时输入和 ARM runc 的可复现构建；它们不等于 ARM 候选已安装或可对客户交付。ARM 候选归档、干净 Ubuntu 安装、服务启动、容器部署和公开访问仍须按各自验收层完成。

宿主的共享 libseccomp/libc 不打进 AcornFox 归档，也不锁死用户提供的接口兼容共享库字节。实际 Ubuntu 包版权文本存于 `native-licenses/`；runc、Go 及其依赖的上游完整许可材料存于 `docs/licenses/licenses-manifest.json`。runc 源码及 vendor 未修改，只有构建元数据使用 `+acornfox.1` 标记。
