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
    VERSION="latest"
    BINARY_NAME="acornfox"

    if [ "$OS" = "windows" ]; then
        BINARY_NAME="acornfox.exe"
    fi

    DOWNLOAD_URL="https://github.com/acornfox/acornfox/releases/download/${VERSION}/acornfox_${OS}_${ARCH}"

    # 中国用户使用代理
    if curl -s -m 2 "http://ip-api.com/json/?fields=countryCode" 2>/dev/null | grep -q '"countryCode":"CN"'; then
        DOWNLOAD_URL="https://ghproxy.com/${DOWNLOAD_URL}"
        log_info "使用中国镜像加速"
    fi

    log_info "下载 AcornFox CLI..."
    log_info "URL: $DOWNLOAD_URL"

    TMP_FILE="/tmp/${BINARY_NAME}"

    if command -v curl >/dev/null 2>&1; then
        curl -fSL --progress-bar "$DOWNLOAD_URL" -o "$TMP_FILE" || error_exit "下载失败"
    elif command -v wget >/dev/null 2>&1; then
        wget -q --show-progress "$DOWNLOAD_URL" -O "$TMP_FILE" || error_exit "下载失败"
    else
        error_exit "需要 curl 或 wget"
    fi

    chmod +x "$TMP_FILE"
}

# 安装 CLI
install_cli() {
    if [ "$OS" = "windows" ]; then
        INSTALL_DIR="$HOME/AppData/Local/AcornFox"
        mkdir -p "$INSTALL_DIR"
        mv "/tmp/acornfox.exe" "$INSTALL_DIR/acornfox.exe"

        log_success "已安装到: $INSTALL_DIR"
        echo ""
        log_info "请将以下路径添加到 PATH 环境变量:"
        echo "  $INSTALL_DIR"
    else
        # Linux/macOS
        if [ -w "/usr/local/bin" ]; then
            mv "/tmp/acornfox" "/usr/local/bin/acornfox"
            log_success "已安装到: /usr/local/bin/acornfox"
        else
            sudo mv "/tmp/acornfox" "/usr/local/bin/acornfox"
            log_success "已安装到: /usr/local/bin/acornfox (需要 sudo)"
        fi
    fi
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
帮助: acornfox --help

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

EOF
}

main() {
    echo ""
    log_info "AcornFox CLI 安装脚本"
    echo ""

    detect_platform
    download_cli
    install_cli

    if verify_installation; then
        show_usage
    else
        error_exit "安装失败"
    fi
}

main "$@"
