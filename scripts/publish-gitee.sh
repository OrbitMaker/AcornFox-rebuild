#!/usr/bin/env bash
# 把一个已发布到 GitHub 的版本同步到 Gitee 国内镜像：推送 main 与标签、创建发行版、上传 dist/ 下的文件。
# 先运行 scripts/build-release.sh vX.Y.Z 并发布 GitHub Release，再运行本脚本。
# 用法: scripts/publish-gitee.sh v0.2.1
# 令牌：环境变量 GITEE_TOKEN，或文件 ~/.config/acornfox/gitee-token（需 projects 权限）。

set -euo pipefail

VERSION="${1:?用法: $0 vX.Y.Z}"
GITEE_REPO="${GITEE_REPO:-VIP13390/AcornFox-rebuild}"
GITEE_USER="${GITEE_REPO%%/*}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIST="$ROOT/dist"
API="https://gitee.com/api/v5/repos/${GITEE_REPO}"
TOKEN_FILE="${HOME}/.config/acornfox/gitee-token"

if [ -z "${GITEE_TOKEN:-}" ]; then
    [ -r "$TOKEN_FILE" ] || { echo "缺少 Gitee 令牌：设置 GITEE_TOKEN 或写入 $TOKEN_FILE" >&2; exit 1; }
    GITEE_TOKEN=$(cat "$TOKEN_FILE")
fi
export GITEE_TOKEN

[ -f "$DIST/SHA256SUMS" ] || { echo "dist/SHA256SUMS 不存在，先运行 scripts/build-release.sh $VERSION" >&2; exit 1; }
grep -q "${VERSION#v}" <("$DIST/acornfox_$(uname -s | tr '[:upper:]' '[:lower:]')_$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')" version) \
    || { echo "dist/ 中的二进制不是 $VERSION，先重新运行 scripts/build-release.sh $VERSION" >&2; exit 1; }
git -C "$ROOT" rev-parse -q --verify "refs/tags/$VERSION" >/dev/null || { echo "本地没有标签 $VERSION" >&2; exit 1; }

# 令牌经 askpass 从环境变量读取，不写进 git 配置或远程地址
ASKPASS=$(mktemp)
trap 'rm -f "$ASKPASS"' EXIT
printf '#!/bin/sh\ncase "$1" in Username*) echo %s;; *) printf %%s "$GITEE_TOKEN";; esac\n' "$GITEE_USER" > "$ASKPASS"
chmod 700 "$ASKPASS"

echo "推送 main 与 $VERSION 到 gitee.com/$GITEE_REPO"
GIT_ASKPASS="$ASKPASS" GIT_TERMINAL_PROMPT=0 git -C "$ROOT" -c credential.helper= push \
    "https://gitee.com/${GITEE_REPO}.git" "refs/tags/${VERSION}^{commit}:refs/heads/main" "refs/tags/${VERSION}:refs/tags/${VERSION}"

# 已有同名发行版则复用，否则创建
RELEASE_ID=$(curl -fsS "${API}/releases/tags/${VERSION}?access_token=${GITEE_TOKEN}" 2>/dev/null \
    | python3 -c 'import sys,json; print(json.load(sys.stdin).get("id") or "")' 2>/dev/null || true)
if [ -z "$RELEASE_ID" ]; then
    BODY="GitHub 主仓库 OrbitMaker/AcornFox-rebuild 的国内镜像发行版，文件与 GitHub Release 相同（见 SHA256SUMS）。完整说明：https://github.com/OrbitMaker/AcornFox-rebuild/releases/tag/${VERSION}"
    RELEASE_ID=$(python3 -c 'import json,sys; print(json.dumps({"access_token":sys.argv[1],"tag_name":sys.argv[2],"name":"AcornFox "+sys.argv[2],"body":sys.argv[3],"target_commitish":"main","prerelease":False}))' \
            "$GITEE_TOKEN" "$VERSION" "$BODY" \
        | curl -fsS -X POST "${API}/releases" -H 'Content-Type: application/json' --data @- \
        | python3 -c 'import sys,json; print(json.load(sys.stdin)["id"])')
    echo "已创建发行版 $VERSION（id $RELEASE_ID）"
else
    echo "复用已有发行版 $VERSION（id $RELEASE_ID）"
fi

# 已上传的同名附件跳过，便于中断后重跑
EXISTING=$(curl -fsS "${API}/releases/${RELEASE_ID}/attach_files?access_token=${GITEE_TOKEN}&per_page=100" \
    | python3 -c 'import sys,json; print("\n".join(a["name"] for a in json.load(sys.stdin)))')
for f in "$DIST"/*; do
    name=$(basename "$f")
    if grep -qxF "$name" <<<"$EXISTING"; then
        echo "  已存在，跳过 $name"
        continue
    fi
    curl -fsS -X POST "${API}/releases/${RELEASE_ID}/attach_files" -F "access_token=${GITEE_TOKEN}" -F "file=@${f}" >/dev/null
    echo "  已上传 $name"
done

echo "完成：https://gitee.com/${GITEE_REPO}/releases/tag/${VERSION}"
echo "提醒：Gitee 社区版单仓库附件总量 1GB，旧版本附件需定期删除。"
