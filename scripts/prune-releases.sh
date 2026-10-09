#!/usr/bin/env bash
# 只保留最新的 N 个发行版（默认 2 个），删除 GitHub 与 Gitee 上更早的发行版及其附件。
# git 标签保留，便于按版本找回代码。Gitee 社区版单仓库附件总量 1GB，每次发版后运行一次。
# 用法: scripts/prune-releases.sh [N]
# Gitee 令牌：环境变量 GITEE_TOKEN，或文件 ~/.config/acornfox/gitee-token。

set -euo pipefail

KEEP="${1:-2}"
GITHUB_REPO="${GITHUB_REPO:-OrbitMaker/AcornFox-rebuild}"
GITEE_REPO="${GITEE_REPO:-VIP13390/AcornFox-rebuild}"
TOKEN_FILE="${HOME}/.config/acornfox/gitee-token"

[[ "$KEEP" =~ ^[1-9][0-9]*$ ]] || { echo "保留数量必须是正整数" >&2; exit 1; }
if [ -z "${GITEE_TOKEN:-}" ]; then
    [ -r "$TOKEN_FILE" ] || { echo "缺少 Gitee 令牌：设置 GITEE_TOKEN 或写入 $TOKEN_FILE" >&2; exit 1; }
    GITEE_TOKEN=$(cat "$TOKEN_FILE")
fi

# 按 vX.Y.Z 的三段数字从新到旧排序，输出保留数量之外的旧版本
older() { sed 's/^v//' | sort -t. -k1,1nr -k2,2nr -k3,3nr | sed 's/^/v/' | tail -n +"$((KEEP + 1))"; }
# DRY_RUN=1 只列出将删除的版本
run() { if [ -n "${DRY_RUN:-}" ]; then echo "  [演练] $*" | sed "s/access_token=[^&]*/access_token=***/"; else "$@"; fi; }

echo "GitHub ${GITHUB_REPO}：保留最新 ${KEEP} 个"
gh release list --repo "$GITHUB_REPO" --limit 100 --json tagName --jq '.[].tagName' | older | while read -r tag; do
    run gh release delete "$tag" --repo "$GITHUB_REPO" --yes
    [ -n "${DRY_RUN:-}" ] || echo "  已删除发行版 ${tag}（标签保留）"
done

echo "Gitee ${GITEE_REPO}：保留最新 ${KEEP} 个"
API="https://gitee.com/api/v5/repos/${GITEE_REPO}"
LIST=$(curl -fsS "${API}/releases?access_token=${GITEE_TOKEN}&per_page=100" \
    | python3 -c 'import sys,json; [print(r["tag_name"], r["id"]) for r in json.load(sys.stdin)]')
for tag in $(awk '{print $1}' <<<"$LIST" | older); do
    id=$(awk -v t="$tag" '$1 == t {print $2}' <<<"$LIST")
    run curl -fsS -o /dev/null -X DELETE "${API}/releases/${id}?access_token=${GITEE_TOKEN}"
    [ -n "${DRY_RUN:-}" ] || echo "  已删除发行版 ${tag}（标签保留）"
done
