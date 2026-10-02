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
        VERSION=$(github_latest_tag) || error_exit "无法获取最新版本号；用 bash install-cli.sh vX.Y.Z 指定版本"
        log_info "最新版本: $VERSION"
    fi

    BINARY_NAME="acornfox"
    ASSET="acornfox_${OS}_${ARCH}"
    if [ "$OS" = "windows" ]; then
        BINARY_NAME="acornfox.exe"
        ASSET="${ASSET}.exe"
    fi

    DOWNLOAD_URL="https://github.com/${ACORNFOX_REPO}/releases/download/${VERSION}/${ASSET}"
    log_info "下载 AcornFox CLI: $DOWNLOAD_URL"

    TMP_DIR=$(mktemp -d)
    TMP_FILE="${TMP_DIR}/${BINARY_NAME}"
    github_download "$DOWNLOAD_URL" "$TMP_FILE" || error_exit "下载失败；可设置 ACORNFOX_GITHUB_PROXY 指定 GitHub 加速地址"
    chmod +x "$TMP_FILE"
}

# GitHub 仓库与下载代理（与 install.sh 一致）
ACORNFOX_REPO="${ACORNFOX_REPO:-acornfox/acornfox}"
GITHUB_PROXIES=()

setup_github_proxies() {
    GITHUB_PROXIES=("")
    if [ -n "${ACORNFOX_GITHUB_PROXY:-}" ]; then
        GITHUB_PROXIES+=("${ACORNFOX_GITHUB_PROXY%/}/")
    fi
    if curl -s -m 3 "http://ip-api.com/json/?fields=countryCode" 2>/dev/null | grep -q '"countryCode":"CN"'; then
        GITHUB_PROXIES+=("https://ghfast.top/" "https://gh-proxy.com/")
    fi
}

github_download() {
    local url="$1" out="$2" p
    for p in "${GITHUB_PROXIES[@]}"; do
        if [ -n "$p" ]; then
            log_info "尝试通过 ${p} 下载"
        fi
        if curl -fL --progress-bar --connect-timeout 10 --max-time 600 --retry 2 -o "$out" "${p}${url}"; then
            return 0
        fi
    done
    return 1
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
        # Linux/macOS
        if [ -w "/usr/local/bin" ]; then
            mv "$TMP_FILE" "/usr/local/bin/acornfox"
            log_success "已安装到: /usr/local/bin/acornfox"
        else
            sudo mv "$TMP_FILE" "/usr/local/bin/acornfox"
            log_success "已安装到: /usr/local/bin/acornfox (需要 sudo)"
        fi
        # macOS 会给下载的文件加隔离属性，去掉以免首次运行被拦截
        if [ "$OS" = "darwin" ]; then
            xattr -d com.apple.quarantine /usr/local/bin/acornfox 2>/dev/null || true
        fi
    fi
    rmdir "$TMP_DIR" 2>/dev/null || true
}

# 验证安装
verify_installation() {
    if command -v acornfox >/dev/null 2>&1; then
        VERSION=$(acornfox version 2>/dev/null || echo "unknown")
        log_success "安装成功！版本: $VERSION"
        return 0
    else
        log_error "安装验证失败"
        return 1
    fi
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

文档: https://acornfox.dev/docs

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
