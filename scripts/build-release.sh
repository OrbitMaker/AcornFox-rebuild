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

echo "完成：$DIST"
ls -l "$DIST"
