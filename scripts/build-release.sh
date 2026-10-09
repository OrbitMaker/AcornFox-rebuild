#!/usr/bin/env bash
# 构建发布产物：dist/acornfox_<os>_<arch>[.exe] 和 SHA256SUMS
# 文件名与 scripts/install/*.sh 下载的地址一致。
# 用法: scripts/build-release.sh v0.2.0

set -euo pipefail

VERSION="${1:?用法: $0 vX.Y.Z}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIST="$ROOT/dist"
LDFLAGS="-s -w -X github.com/acornfox/acornfox/internal/cli.Version=${VERSION#v}"

rm -rf "$DIST"
mkdir -p "$DIST"

cd "$ROOT/acornfox"
for target in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64; do
    os="${target%/*}"
    arch="${target#*/}"
    out="$DIST/acornfox_${os}_${arch}"
    [ "$os" = "windows" ] && out="${out}.exe"
    echo "构建 ${os}/${arch}"
    CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -trimpath -ldflags "$LDFLAGS" -o "$out" ./cmd/acornfox
done

cd "$DIST"
if command -v sha256sum >/dev/null 2>&1; then
    sha256sum acornfox_* > SHA256SUMS
else
    shasum -a 256 acornfox_* > SHA256SUMS
fi
cp "$ROOT/scripts/install/install.sh" "$ROOT/scripts/install/upgrade.sh" "$ROOT/scripts/install/install-cli.sh" "$DIST/"

# install.sh 在中国大陆先从 Gitee 发行版取 Caddy，所以随每个版本附带同一份官方安装包、
# 校验文件与许可证（Apache-2.0）。版本号以 install.sh 为准，下载后按官方 SHA-512 校验。
CADDY_VERSION=$(sed -n 's/^ *CADDY_VERSION="\([0-9.]*\)"$/\1/p' "$ROOT/scripts/install/install.sh" | head -1)
[ -n "$CADDY_VERSION" ] || { echo "无法从 install.sh 读取 CADDY_VERSION" >&2; exit 1; }
CADDY_URL="https://github.com/caddyserver/caddy/releases/download/v${CADDY_VERSION}"
echo "下载 Caddy ${CADDY_VERSION}"
curl -fsSL -o "caddy_${CADDY_VERSION}_checksums.txt" "${CADDY_URL}/caddy_${CADDY_VERSION}_checksums.txt"
curl -fsSL -o caddy_LICENSE "https://raw.githubusercontent.com/caddyserver/caddy/v${CADDY_VERSION}/LICENSE"
for arch in amd64 arm64; do
    f="caddy_${CADDY_VERSION}_linux_${arch}.tar.gz"
    curl -fsSL -o "$f" "${CADDY_URL}/${f}"
    want=$(awk -v a="$f" '$2 == a {print $1; exit}' "caddy_${CADDY_VERSION}_checksums.txt")
    if command -v sha512sum >/dev/null 2>&1; then
        got=$(sha512sum "$f" | awk '{print $1}')
    else
        got=$(shasum -a 512 "$f" | awk '{print $1}')
    fi
    [ -n "$want" ] && [ "$got" = "$want" ] || { echo "$f SHA-512 校验失败" >&2; exit 1; }
done

echo "完成：$DIST"
ls -l "$DIST"
