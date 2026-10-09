#!/usr/bin/env bash
# AcornFox CLI 客户端安装脚本
# 支持: Windows, macOS, Linux (amd64/arm64)

set -euo pipefail

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
error_exit() { log_error "$1"; exit 1; }

# 检测操作系统和架构
detect_platform() {
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    ARCH=$(uname -m)

    case "$OS" in
        linux)
            OS="linux"
            ;;
        darwin)
            OS="darwin"
            ;;
        mingw*|msys*|cygwin*)
            OS="windows"
            ;;
        *)
            error_exit "不支持的操作系统: $OS"
            ;;
    esac

    case "$ARCH" in
        x86_64|amd64)
            ARCH="amd64"
            ;;
        aarch64|arm64)
            ARCH="arm64"
            ;;
        *)
            error_exit "不支持的架构: $ARCH"
            ;;
    esac

    log_info "检测到平台: ${OS}/${ARCH}"
}

# 下载 CLI
download_cli() {
    VERSION="${1:-latest}"

    command -v curl >/dev/null 2>&1 || error_exit "需要 curl"
    setup_github_proxies

    if [ "$VERSION" = "latest" ]; then
        log_info "获取最新版本号..."
        VERSION=$(latest_tag) || error_exit "无法获取最新版本号；用 bash install-cli.sh vX.Y.Z 指定版本"
        log_info "最新版本: $VERSION"
    fi

    BINARY_NAME="acornfox"
    ASSET="acornfox_${OS}_${ARCH}"
    if [ "$OS" = "windows" ]; then
        BINARY_NAME="acornfox.exe"
        ASSET="${ASSET}.exe"
    fi

    log_info "下载 AcornFox CLI ${VERSION}（${ASSET}）"

    TMP_DIR=$(mktemp -d)
    TMP_FILE="${TMP_DIR}/${BINARY_NAME}"
    release_download "$VERSION" "$ASSET" "$TMP_FILE" || error_exit "下载失败；可设置 ACORNFOX_GITHUB_PROXY 指定 GitHub 加速地址"
    verify_sha256 "$TMP_FILE" "$ASSET" "$VERSION"
    chmod +x "$TMP_FILE"
}

# GitHub 仓库与下载代理（与 install.sh 一致）
ACORNFOX_REPO="${ACORNFOX_REPO:-OrbitMaker/AcornFox-rebuild}"
GITHUB_PROXIES=()

# detect_china：先查阿里云、腾讯云元数据，再问 ip-api（它偶尔要 2 秒以上才响应，放宽超时并试两次）
detect_china() {
    curl -fs -m 2 http://100.100.100.200/latest/meta-data/region-id 2>/dev/null | grep -q '^cn-' && return 0
    curl -fs -m 2 http://metadata.tencentyun.com/latest/meta-data/placement/region 2>/dev/null \
        | grep -qE '^ap-(beijing|shanghai|guangzhou|chengdu|chongqing|nanjing)' && return 0
    local i
    for i in 1 2; do
        curl -s -m 5 "http://ip-api.com/json/?fields=countryCode" 2>/dev/null | grep -q '"countryCode":"CN"' && return 0
    done
    return 1
}

setup_github_proxies() {
    GITHUB_PROXIES=("")
    if [ -n "${ACORNFOX_GITHUB_PROXY:-}" ]; then
        GITHUB_PROXIES+=("${ACORNFOX_GITHUB_PROXY%/}/")
    fi
    IN_CHINA=false
    if detect_china; then
        IN_CHINA=true
        GITHUB_PROXIES+=("https://ghfast.top/" "https://gh-proxy.com/")
    fi
}

github_download() {
    local url="$1" out="$2" p
    # 连续 15 秒低于 50KB/s 就放弃当前源换下一个：国内直连 GitHub 常只有十几 KB/s，
    # 不限速时要等满 --max-time 才会轮到代理。所有源都太慢时，最后不限速再试一次。
    for p in "${GITHUB_PROXIES[@]}"; do
        if [ -n "$p" ]; then
            log_info "尝试通过 ${p} 下载"
        fi
        if curl -fL --progress-bar --connect-timeout 10 --max-time 600 --speed-limit 51200 --speed-time 15 -o "$out" "${p}${url}"; then
            return 0
        fi
    done
    log_info "所有下载源都较慢，不限速重试一次"
    curl -fL --progress-bar --connect-timeout 10 --max-time 1800 --retry 2 -o "$out" "${GITHUB_PROXIES[0]}${url}"
}

# 国内镜像：Gitee 发行版与 GitHub Release 的文件相同（同一份 SHA256SUMS 校验）。
# 中国大陆服务器先从 Gitee 下载，失败再走 GitHub 直连和代理；ACORNFOX_GITEE_REPO 设为空可关闭。
ACORNFOX_GITEE_REPO="${ACORNFOX_GITEE_REPO-VIP13390/AcornFox-rebuild}"

# release_download VERSION ASSET OUT：下载某个版本的 Release 文件
release_download() {
    local version="$1" asset="$2" out="$3"
    if $IN_CHINA && [ -n "$ACORNFOX_GITEE_REPO" ]; then
        log_info "从 Gitee 镜像下载 ${asset}"
        if curl -fL --connect-timeout 10 --max-time 600 --speed-limit 51200 --speed-time 15 -o "$out" \
            "https://gitee.com/${ACORNFOX_GITEE_REPO}/releases/download/${version}/${asset}"; then
            return 0
        fi
        log_warn "Gitee 镜像下载失败，改从 GitHub 下载"
    fi
    github_download "https://github.com/${ACORNFOX_REPO}/releases/download/${version}/${asset}" "$out"
}

# latest_tag：最新版本号。中国大陆先查 Gitee 发行版 API（Gitee 的 releases/latest
# 页面不跳转到版本页，不能沿用 GitHub 的做法），再走 GitHub 的 releases/latest 跳转
latest_tag() {
    local tag
    if $IN_CHINA && [ -n "$ACORNFOX_GITEE_REPO" ]; then
        tag=$(curl -fsS -m 15 "https://gitee.com/api/v5/repos/${ACORNFOX_GITEE_REPO}/releases/latest" 2>/dev/null \
            | grep -o '"tag_name":"[^"]*"' | head -1 | cut -d'"' -f4)
        if [ -n "$tag" ]; then
            echo "$tag"
            return 0
        fi
    fi
    github_latest_tag
}

# verify_sha256 FILE ASSET VERSION：用同一 Release 的 SHA256SUMS 校验下载文件，不一致则删除并中止。
# 能发现下载损坏和镜像代理被篡改的单个文件；SHA256SUMS 与二进制走同一通道，防不了整个发布源被替换。
verify_sha256() {
    local file="$1" asset="$2" version="$3" sums want got
    sums=$(mktemp)
    if ! release_download "$version" SHA256SUMS "$sums"; then
        rm -f "$sums" "$file"
        error_exit "下载 SHA256SUMS 失败，无法校验 ${asset}"
    fi
    want=$(awk -v a="$asset" '$2 == a || $2 == "*" a {print $1; exit}' "$sums")
    rm -f "$sums"
    if [ -z "$want" ]; then
        rm -f "$file"
        error_exit "SHA256SUMS 中没有 ${asset}"
    fi
    if command -v sha256sum >/dev/null 2>&1; then
        got=$(sha256sum "$file" | awk '{print $1}')
    else
        got=$(shasum -a 256 "$file" | awk '{print $1}')
    fi
    if [ "$got" != "$want" ]; then
        rm -f "$file"
        error_exit "${asset} SHA256 校验失败：期望 ${want}，实际 ${got}"
    fi
    log_success "SHA256 校验通过: ${asset}"
}

github_latest_tag() {
    local p loc
    for p in "${GITHUB_PROXIES[@]}"; do
        loc=$(curl -fsSIL --connect-timeout 10 --max-time 30 -o /dev/null -w '%{url_effective}' \
            "${p}https://github.com/${ACORNFOX_REPO}/releases/latest" 2>/dev/null || true)
        case "$loc" in
            */releases/tag/*)
                echo "${loc##*/}"
                return 0
                ;;
        esac
    done
    return 1
}

# 安装 CLI
install_cli() {
    if [ "$OS" = "windows" ]; then
        INSTALL_DIR="$HOME/AppData/Local/AcornFox"
        mkdir -p "$INSTALL_DIR"
        mv "$TMP_FILE" "$INSTALL_DIR/acornfox.exe"

        log_success "已安装到: $INSTALL_DIR"
        echo ""
        log_info "请将以下路径添加到 PATH 环境变量:"
        echo "  $INSTALL_DIR"
    else
        # Linux/macOS：不使用 sudo。AI 工作台在后台执行时无法输入密码，Apple 芯片的 Mac 上
        # /usr/local/bin 默认也需要 sudo。依次选择：ACORNFOX_INSTALL_DIR、已安装位置（就地升级，
        # 避免新旧两份并存）、可写的 /usr/local/bin、~/.local/bin。
        local existing=""
        existing=$(command -v acornfox 2>/dev/null || true)
        if [ -n "${ACORNFOX_INSTALL_DIR:-}" ]; then
            INSTALL_DIR="$ACORNFOX_INSTALL_DIR"
        elif [ -n "$existing" ] && [ -w "$(dirname "$existing")" ]; then
            INSTALL_DIR=$(dirname "$existing")
        elif [ -w "/usr/local/bin" ]; then
            INSTALL_DIR="/usr/local/bin"
        else
            INSTALL_DIR="${HOME}/.local/bin"
        fi
        mkdir -p "$INSTALL_DIR" || error_exit "无法创建安装目录 ${INSTALL_DIR}；可用 ACORNFOX_INSTALL_DIR 指定可写目录"
        [ -w "$INSTALL_DIR" ] || error_exit "安装目录 ${INSTALL_DIR} 不可写；可用 ACORNFOX_INSTALL_DIR 指定可写目录"
        mv "$TMP_FILE" "${INSTALL_DIR}/acornfox"
        # macOS 会给下载的文件加隔离属性，去掉以免首次运行被拦截
        if [ "$OS" = "darwin" ]; then
            xattr -d com.apple.quarantine "${INSTALL_DIR}/acornfox" 2>/dev/null || true
        fi
        log_success "已安装到: ${INSTALL_DIR}/acornfox"
    fi
    rmdir "$TMP_DIR" 2>/dev/null || true
}

# 验证安装
verify_installation() {
    local bin="${INSTALL_DIR}/acornfox"
    [ "$OS" = "windows" ] && bin="${INSTALL_DIR}/acornfox.exe"
    VERSION=$("$bin" version 2>/dev/null) || { log_error "安装验证失败: ${bin} 无法运行"; return 1; }
    log_success "安装成功！版本: ${VERSION}"
    [ "$OS" = "windows" ] && return 0
    local found
    found=$(command -v acornfox 2>/dev/null || true)
    if [ -z "$found" ]; then
        log_warn "${INSTALL_DIR} 不在 PATH 中。把下面这行加入 ~/.zshrc 或 ~/.bashrc 后重新打开终端，或直接用完整路径 ${bin}："
        echo "  export PATH=\"${INSTALL_DIR}:\$PATH\""
    elif [ "$found" != "$bin" ]; then
        log_warn "PATH 中优先找到的是另一个 acornfox：${found}（$("$found" version 2>/dev/null || echo 未知版本)），请删除它或调整 PATH 顺序"
    fi
    return 0
}

# 显示使用说明
show_usage() {
    cat << 'EOF'

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✓ AcornFox CLI 安装完成！
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

下一步:

1. 配置服务器连接:
   acornfox target add my-server --ssh user@your-server

2. 部署你的第一个应用:
   cd your-project
   acornfox deploy

3. 安装 AI 工作台 Skill:
   acornfox skill install

文档: https://github.com/OrbitMaker/AcornFox-rebuild/tree/main/docs

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

EOF
}

main() {
    echo ""
    log_info "AcornFox CLI 安装脚本"
    echo ""

    detect_platform
    download_cli "${1:-latest}"
    install_cli

    if verify_installation; then
        show_usage
    else
        error_exit "安装失败"
    fi
}

main "$@"
