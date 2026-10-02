#!/usr/bin/env bash
# AcornFox 安装脚本
# 用途: 在干净的 Linux 系统上一键安装 AcornFox
# 支持: Ubuntu 24.04/22.04/20.04, Debian 12/11
# 许可: AGPL-3.0

set -euo pipefail

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 日志函数
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# 错误处理
error_exit() {
    log_error "$1"
    exit 1
}

# 检查 root 权限
check_root() {
    if [ "$EUID" -ne 0 ]; then
        error_exit "请使用 sudo 运行此脚本"
    fi
}

# 检测操作系统
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
        OS_VERSION=$VERSION_ID
        OS_CODENAME=${VERSION_CODENAME:-}
    else
        error_exit "无法检测操作系统"
    fi

    log_info "检测到操作系统: $OS $OS_VERSION"

    case "$OS" in
        ubuntu)
            if [[ ! "$OS_VERSION" =~ ^(20.04|22.04|24.04)$ ]]; then
                log_warn "未测试的 Ubuntu 版本: $OS_VERSION，继续安装可能遇到问题"
            fi
            ;;
        debian)
            if [[ ! "$OS_VERSION" =~ ^(11|12)$ ]]; then
                log_warn "未测试的 Debian 版本: $OS_VERSION，继续安装可能遇到问题"
            fi
            ;;
        *)
            error_exit "不支持的操作系统: $OS，目前仅支持 Ubuntu 和 Debian"
            ;;
    esac
}

# 检测地理位置（判断是否在中国大陆）
detect_location() {
    log_info "检测服务器地理位置..."

    IN_CHINA=false

    # 方法 1: 检查云厂商元数据
    # 阿里云
    if curl -s -m 2 http://100.100.100.200/latest/meta-data/region-id 2>/dev/null | grep -q "cn-"; then
        IN_CHINA=true
        log_info "检测到阿里云中国区域"
        return
    fi

    # 腾讯云
    if curl -s -m 2 http://metadata.tencentyun.com/latest/meta-data/placement/region 2>/dev/null | grep -q "ap-"; then
        if curl -s -m 2 http://metadata.tencentyun.com/latest/meta-data/placement/region 2>/dev/null | grep -qE "ap-beijing|ap-shanghai|ap-guangzhou|ap-chengdu|ap-chongqing"; then
            IN_CHINA=true
            log_info "检测到腾讯云中国区域"
            return
        fi
    fi

    # 华为云
    if curl -s -m 2 http://169.254.169.254/openstack/latest/meta_data.json 2>/dev/null | grep -q "cn-"; then
        IN_CHINA=true
        log_info "检测到华为云中国区域"
        return
    fi

    # 方法 2: IP 地理位置检测（回退方案）
    if command -v curl >/dev/null 2>&1; then
        COUNTRY=$(curl -s -m 5 "http://ip-api.com/json/?fields=countryCode" 2>/dev/null | grep -o '"countryCode":"[^"]*"' | cut -d'"' -f4)
        if [ "$COUNTRY" = "CN" ]; then
            IN_CHINA=true
            log_info "通过 IP 检测到中国大陆"
            return
        fi
    fi

    log_info "检测为非中国大陆环境"
}

# 处理命令行参数
parse_args() {
    FORCE_CHINA=false
    FORCE_GLOBAL=false
    SKIP_DOCKER=false
    SKIP_CADDY=false

    while [[ $# -gt 0 ]]; do
        case $1 in
            --china)
                FORCE_CHINA=true
                shift
                ;;
            --global)
                FORCE_GLOBAL=true
                shift
                ;;
            --skip-docker)
                SKIP_DOCKER=true
                shift
                ;;
            --skip-caddy)
                SKIP_CADDY=true
                shift
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            *)
                error_exit "未知参数: $1\n使用 --help 查看帮助"
                ;;
        esac
    done

    # 手动覆盖自动检测
    if $FORCE_CHINA; then
        IN_CHINA=true
        log_info "手动指定使用中国镜像源"
    elif $FORCE_GLOBAL; then
        IN_CHINA=false
        log_info "手动指定使用国际源"
    fi
}

# 显示帮助
show_help() {
    cat << EOF
AcornFox 安装脚本

用法:
    sudo bash install.sh [选项]

选项:
    --china          强制使用中国镜像源
    --global         强制使用国际源
    --skip-docker    跳过 Docker 安装（如已安装）
    --skip-caddy     跳过 Caddy 安装（如已安装）
    -h, --help       显示此帮助信息

示例:
    # 自动检测并安装
    sudo bash install.sh

    # 强制使用中国镜像源
    sudo bash install.sh --china

    # 跳过已安装的 Docker
    sudo bash install.sh --skip-docker

EOF
}

# 更新软件包列表
update_apt() {
    log_info "更新软件包列表..."

    # 如果在中国，配置 APT 使用国内镜像
    if $IN_CHINA; then
        log_info "配置 APT 使用国内镜像..."
        case "$OS" in
            ubuntu)
                # 备份原始源
                cp /etc/apt/sources.list /etc/apt/sources.list.bak || true

                # 使用阿里云镜像
                cat > /etc/apt/sources.list << EOF
deb http://mirrors.aliyun.com/ubuntu/ ${OS_CODENAME} main restricted universe multiverse
deb http://mirrors.aliyun.com/ubuntu/ ${OS_CODENAME}-updates main restricted universe multiverse
deb http://mirrors.aliyun.com/ubuntu/ ${OS_CODENAME}-backports main restricted universe multiverse
deb http://mirrors.aliyun.com/ubuntu/ ${OS_CODENAME}-security main restricted universe multiverse
EOF
                ;;
            debian)
                cp /etc/apt/sources.list /etc/apt/sources.list.bak || true

                cat > /etc/apt/sources.list << EOF
deb http://mirrors.aliyun.com/debian/ ${OS_CODENAME} main contrib non-free
deb http://mirrors.aliyun.com/debian/ ${OS_CODENAME}-updates main contrib non-free
deb http://mirrors.aliyun.com/debian-security ${OS_CODENAME}-security main contrib non-free
EOF
                ;;
        esac
    fi

    apt-get update -qq || error_exit "更新软件包列表失败"
}

# 安装基础依赖
install_dependencies() {
    log_info "安装基础依赖..."
    apt-get install -y -qq \
        curl \
        wget \
        ca-certificates \
        gnupg \
        lsb-release \
        apt-transport-https \
        software-properties-common \
        || error_exit "安装基础依赖失败"
}

# 安装 Docker
install_docker() {
    if $SKIP_DOCKER; then
        log_info "跳过 Docker 安装"
        return
    fi

    if command -v docker >/dev/null 2>&1; then
        DOCKER_VERSION=$(docker --version | awk '{print $3}' | tr -d ',')
        log_info "Docker 已安装: $DOCKER_VERSION"
        return
    fi

    log_info "安装 Docker..."

    if $IN_CHINA; then
        # 使用阿里云 Docker 镜像源
        log_info "使用阿里云 Docker 镜像源..."

        # 添加阿里云 Docker GPG 密钥
        curl -fsSL https://mirrors.aliyun.com/docker-ce/linux/${OS}/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg

        # 添加阿里云 Docker 仓库
        echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://mirrors.aliyun.com/docker-ce/linux/${OS} ${OS_CODENAME} stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
    else
        # 使用 Docker 官方源
        log_info "使用 Docker 官方源..."

        # 添加 Docker 官方 GPG 密钥
        curl -fsSL https://download.docker.com/linux/${OS}/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg

        # 添加 Docker 官方仓库
        echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/${OS} ${OS_CODENAME} stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
    fi

    # 安装 Docker
    apt-get update -qq
    apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin || error_exit "Docker 安装失败"

    # 启动 Docker
    systemctl enable docker
    systemctl start docker

    # 验证安装
    if docker --version >/dev/null 2>&1; then
        log_success "Docker 安装成功: $(docker --version)"
    else
        error_exit "Docker 安装验证失败"
    fi
}

# 配置 Docker 镜像加速
configure_docker_mirror() {
    log_info "配置 Docker 镜像加速..."

    if ! $IN_CHINA; then
        log_info "非中国环境，跳过镜像加速配置"
        return
    fi

    # 创建 Docker 配置目录
    mkdir -p /etc/docker

    # 配置镜像加速器
    cat > /etc/docker/daemon.json << 'EOF'
{
  "registry-mirrors": [
    "https://registry.cn-hangzhou.aliyuncs.com",
    "https://mirror.ccs.tencentyun.com"
  ],
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  }
}
EOF

    # 重启 Docker
    systemctl daemon-reload
    systemctl restart docker

    log_success "Docker 镜像加速配置完成"
}

# 安装 Caddy
install_caddy() {
    if $SKIP_CADDY; then
        log_info "跳过 Caddy 安装"
        return
    fi

    if command -v caddy >/dev/null 2>&1; then
        CADDY_VERSION=$(caddy version | awk '{print $1}')
        log_info "Caddy 已安装: $CADDY_VERSION"
        return
    fi

    log_info "安装 Caddy..."

    if $IN_CHINA; then
        # 使用 GitHub 加速代理下载
        log_info "通过代理下载 Caddy..."
        ARCH=$(dpkg --print-architecture)
        CADDY_VERSION="2.8.4"

        wget -q --show-progress "https://ghproxy.com/https://github.com/caddyserver/caddy/releases/download/v${CADDY_VERSION}/caddy_${CADDY_VERSION}_linux_${ARCH}.tar.gz" -O /tmp/caddy.tar.gz || error_exit "下载 Caddy 失败"

        tar -xzf /tmp/caddy.tar.gz -C /tmp
        mv /tmp/caddy /usr/bin/caddy
        chmod +x /usr/bin/caddy
        rm -f /tmp/caddy.tar.gz /tmp/LICENSE /tmp/README.md
    else
        # 使用官方 apt 仓库安装
        log_info "使用官方仓库安装 Caddy..."

        # 添加 Caddy GPG 密钥
        curl -fsSL https://dl.cloudsmith.io/public/caddy/stable/gpg.key | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg

        # 添加 Caddy 仓库
        echo "deb [signed-by=/usr/share/keyrings/caddy-stable-archive-keyring.gpg] https://dl.cloudsmith.io/public/caddy/stable/deb/debian any-version main" | tee /etc/apt/sources.list.d/caddy-stable.list

        # 安装 Caddy
        apt-get update -qq
        apt-get install -y -qq caddy || error_exit "Caddy 安装失败"
    fi

    # 验证安装
    if caddy version >/dev/null 2>&1; then
        log_success "Caddy 安装成功: $(caddy version)"
    else
        error_exit "Caddy 安装验证失败"
    fi
}

# 配置 Caddy admin API socket
configure_caddy() {
    if $SKIP_CADDY; then
        log_info "跳过 Caddy 配置"
        return
    fi

    log_info "配置 Caddy admin API socket..."

    # 创建 Caddy 配置目录
    mkdir -p /etc/caddy

    # 创建 Caddyfile，启用 Unix socket admin API
    cat > /etc/caddy/Caddyfile << 'EOF'
{
    admin unix//run/acornfox/caddy-admin.sock {
        origins *
    }
    persist_config off
}

# AcornFox 应用路由将通过 API 动态添加
EOF

    # 设置 Caddyfile 权限
    chown root:root /etc/caddy/Caddyfile
    chmod 644 /etc/caddy/Caddyfile

    # 创建 /run/acornfox 目录并设置权限
    mkdir -p /run/acornfox
    chown acornfox:acornfox /run/acornfox
    chmod 775 /run/acornfox

    # 重启 Caddy 以应用配置
    if systemctl is-active --quiet caddy; then
        systemctl restart caddy
        sleep 2
    fi

    # 验证 admin socket 是否创建
    if [ -S /run/acornfox/caddy-admin.sock ]; then
        # 设置 socket 权限，允许 acornfox 用户访问
        chmod 660 /run/acornfox/caddy-admin.sock
        chown caddy:acornfox /run/acornfox/caddy-admin.sock
        log_success "Caddy admin socket 配置完成"
    else
        log_warn "Caddy admin socket 尚未创建，可能需要手动配置"
    fi
}

# 创建系统账号和组
create_accounts() {
    log_info "创建系统账号和组..."

    # 创建 acornfox-ipc 组（用于 socket 通信）
    if ! getent group acornfox-ipc >/dev/null; then
        groupadd -r acornfox-ipc
        log_success "创建组: acornfox-ipc"
    fi

    # 创建 acornfox-users 组（用于 CLI 访问）
    if ! getent group acornfox-users >/dev/null; then
        groupadd -r acornfox-users
        log_success "创建组: acornfox-users"
    fi

    # 创建 acornfox 用户（运行 server）
    if ! id acornfox >/dev/null 2>&1; then
        useradd -r -s /bin/bash -d /var/lib/acornfox -m -G acornfox-ipc,acornfox-users acornfox
        log_success "创建用户: acornfox"
    fi

    # 创建 acornfox-exec 用户（运行 runner，需要 docker 组权限）
    if ! id acornfox-exec >/dev/null 2>&1; then
        useradd -r -s /bin/bash -d /var/lib/acornfox-exec -m -G docker,acornfox-ipc acornfox-exec
        log_success "创建用户: acornfox-exec"
    else
        # 确保 acornfox-exec 在 docker 组中
        usermod -aG docker acornfox-exec
    fi

    # 修复 Caddy admin socket 权限问题
    # 将 caddy 用户添加到 acornfox 组，允许访问 /run/acornfox/
    if id caddy >/dev/null 2>&1; then
        usermod -aG acornfox caddy
        log_info "已将 caddy 用户添加到 acornfox 组"
    fi

    # 将 acornfox 用户添加到 caddy 组，允许访问 Caddy admin socket
    if getent group caddy >/dev/null; then
        usermod -aG caddy acornfox
        log_info "已将 acornfox 用户添加到 caddy 组"
    fi
}

# 下载 AcornFox 二进制文件
download_acornfox() {
    log_info "下载 AcornFox..."

    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64)
            ARCH="amd64"
            ;;
        aarch64)
            ARCH="arm64"
            ;;
        *)
            error_exit "不支持的架构: $ARCH"
            ;;
    esac

    # 从 GitHub Releases 下载最新版本
    # 格式: https://github.com/acornfox/acornfox/releases/download/v0.2.0/acornfox_linux_amd64
    VERSION="${1:-latest}"

    if [ "$VERSION" = "latest" ]; then
        # 获取最新 release 版本号
        log_info "获取最新版本号..."

        if $IN_CHINA; then
            # 使用代理获取最新版本
            VERSION=$(curl -fsSL "https://ghproxy.com/https://api.github.com/repos/acornfox/acornfox/releases/latest" 2>/dev/null | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/' || echo "v0.2.0")
        else
            VERSION=$(curl -fsSL "https://api.github.com/repos/acornfox/acornfox/releases/latest" 2>/dev/null | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/' || echo "v0.2.0")
        fi

        log_info "最新版本: $VERSION"
    fi

    DOWNLOAD_URL="https://github.com/acornfox/acornfox/releases/download/${VERSION}/acornfox_linux_${ARCH}"

    if $IN_CHINA; then
        # 使用 GitHub 代理
        DOWNLOAD_URL="https://ghproxy.com/${DOWNLOAD_URL}"
        log_info "使用中国镜像加速"
    fi

    log_info "下载地址: $DOWNLOAD_URL"

    # 下载到临时目录
    if wget -q --show-progress "$DOWNLOAD_URL" -O /tmp/acornfox; then
        log_success "下载完成"
    else
        error_exit "下载 AcornFox 失败，请检查网络连接或版本号是否正确"
    fi

    # 安装到 /usr/local/bin
    install -m 0755 /tmp/acornfox /usr/local/bin/acornfox
    rm -f /tmp/acornfox

    # 验证安装
    INSTALLED_VERSION=$(/usr/local/bin/acornfox version 2>/dev/null | awk '{print $2}' || echo "unknown")
    if [ "$INSTALLED_VERSION" != "unknown" ]; then
        log_success "AcornFox 安装成功: $INSTALLED_VERSION"
    else
        error_exit "AcornFox 安装验证失败"
    fi
}

# 创建数据目录
create_directories() {
    log_info "创建数据目录..."

    # 主数据目录
    mkdir -p /var/lib/acornfox/{data,uploads,logs}
    chown -R acornfox:acornfox /var/lib/acornfox
    chmod 750 /var/lib/acornfox

    # runner socket 目录
    mkdir -p /run/acornfox
    chown acornfox-exec:acornfox-ipc /run/acornfox
    chmod 2770 /run/acornfox

    log_success "数据目录创建完成"
}

# 初始化数据库
initialize_database() {
    log_info "初始化数据库..."

    # 使用 acornfox 用户初始化数据库
    su - acornfox -c "/usr/local/bin/acornfox init" || error_exit "数据库初始化失败"

    # 设置数据库文件权限
    chmod 600 /var/lib/acornfox/data/acornfox.db

    log_success "数据库初始化完成"
}

# 生成管理员令牌
generate_admin_token() {
    log_info "生成管理员令牌..."

    # 生成令牌
    TOKEN=$(su - acornfox -c "/usr/local/bin/acornfox admin-token" 2>&1 | tail -n1)

    if [ -z "$TOKEN" ]; then
        error_exit "生成管理员令牌失败"
    fi

    # 保存令牌到文件（仅 root 可读）
    echo "$TOKEN" > /root/.acornfox-token
    chmod 600 /root/.acornfox-token

    log_success "管理员令牌已生成"
}

# 创建 systemd 服务
create_systemd_services() {
    log_info "创建 systemd 服务..."

    # 获取用户 UID（修复 peer credentials 验证问题）
    ACORNFOX_UID=$(id -u acornfox)
    ACORNFOX_EXEC_UID=$(id -u acornfox-exec)

    log_info "配置 UID: acornfox=$ACORNFOX_UID, acornfox-exec=$ACORNFOX_EXEC_UID"

    # acornfox-server.service
    # 重要：添加 --runner-uid 参数，解决 peer credentials 验证问题
    cat > /etc/systemd/system/acornfox-server.service << EOF
[Unit]
Description=AcornFox Server
Documentation=https://acornfox.dev
After=network.target docker.service
Requires=docker.service

[Service]
Type=simple
User=acornfox
Group=acornfox
ExecStart=/usr/local/bin/acornfox server --runner-uid $ACORNFOX_EXEC_UID
Restart=on-failure
RestartSec=5s
StandardOutput=journal
StandardError=journal
SyslogIdentifier=acornfox-server

# 安全加固
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/acornfox /run/acornfox

[Install]
WantedBy=multi-user.target
EOF

    # acornfox-runner.service
    # 重要：添加 --server-uid 参数，解决 peer credentials 验证问题
    cat > /etc/systemd/system/acornfox-runner.service << EOF
[Unit]
Description=AcornFox Runner
Documentation=https://acornfox.dev
After=network.target docker.service
Requires=docker.service

[Service]
Type=simple
User=acornfox-exec
Group=acornfox-exec
ExecStart=/usr/local/bin/acornfox runner --server-uid $ACORNFOX_UID
Restart=on-failure
RestartSec=5s
StandardOutput=journal
StandardError=journal
SyslogIdentifier=acornfox-runner

# 安全加固
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

    # 重新加载 systemd
    systemctl daemon-reload

    log_success "systemd 服务创建完成（已配置正确的 UID 参数）"
}

# 启动服务
start_services() {
    log_info "启动 AcornFox 服务..."

    # 启用并启动服务
    systemctl enable acornfox-server acornfox-runner
    systemctl start acornfox-runner
    sleep 2
    systemctl start acornfox-server

    # 等待服务启动
    sleep 3

    # 检查服务状态
    if systemctl is-active --quiet acornfox-server && systemctl is-active --quiet acornfox-runner; then
        log_success "AcornFox 服务启动成功"
    else
        log_error "服务启动失败，请检查日志:"
        echo "  journalctl -u acornfox-server -n 50"
        echo "  journalctl -u acornfox-runner -n 50"
        exit 1
    fi
}

# 显示安装摘要
show_summary() {
    cat << EOF

${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}
${GREEN}✓ AcornFox 安装完成！${NC}
${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}

${BLUE}服务状态:${NC}
  • acornfox-server: $(systemctl is-active acornfox-server)
  • acornfox-runner: $(systemctl is-active acornfox-runner)

${BLUE}管理员令牌:${NC}
$(cat /root/.acornfox-token)

${BLUE}下一步:${NC}
  1. 在本地电脑安装 CLI:
     ${YELLOW}curl -fsSL https://acornfox.dev/install-cli.sh | bash${NC}

  2. 配置服务器连接:
     ${YELLOW}acornfox target add my-server --ssh user@${HOSTNAME}${NC}

  3. 打开网页控制台:
     ${YELLOW}acornfox open${NC}

${BLUE}文档:${NC}
  https://acornfox.dev/docs

${BLUE}故障排查:${NC}
  查看日志: ${YELLOW}journalctl -u acornfox-server -f${NC}
  查看日志: ${YELLOW}journalctl -u acornfox-runner -f${NC}

${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}

EOF
}

# 主函数
main() {
    echo ""
    log_info "AcornFox 安装脚本"
    log_info "版本: 1.0.0"
    echo ""

    # 检查权限
    check_root

    # 检测环境
    detect_os
    detect_location

    # 解析参数
    parse_args "$@"

    # 安装流程
    update_apt
    install_dependencies
    install_docker
    configure_docker_mirror
    install_caddy
    create_accounts
    configure_caddy
    create_directories
    download_acornfox "${1:-latest}"
    initialize_database
    generate_admin_token
    create_systemd_services
    start_services

    # 显示摘要
    show_summary
}

# 执行主函数
main "$@"
