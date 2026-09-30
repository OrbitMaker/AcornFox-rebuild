#!/usr/bin/env bash
# AcornFox 升级脚本
# 用途: 升级已安装的 AcornFox 服务器端

set -euo pipefail

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

# 检查 root 权限
check_root() {
    if [ "$EUID" -ne 0 ]; then
        error_exit "请使用 sudo 运行此脚本"
    fi
}

# 检查 AcornFox 是否已安装
check_installed() {
    if [ ! -f "/usr/local/bin/acornfox" ]; then
        error_exit "AcornFox 未安装，请先运行 install.sh"
    fi

    CURRENT_VERSION=$(/usr/local/bin/acornfox version 2>/dev/null | awk '{print $2}' || echo "unknown")
    log_info "当前版本: $CURRENT_VERSION"
}

# 备份当前安装
backup_current() {
    BACKUP_DIR="/var/lib/acornfox/backups"
    TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    BACKUP_PATH="${BACKUP_DIR}/${TIMESTAMP}"

    log_info "创建备份..."
    mkdir -p "$BACKUP_PATH"

    # 备份二进制文件
    cp /usr/local/bin/acornfox "${BACKUP_PATH}/acornfox.bin" || error_exit "备份二进制文件失败"

    # 备份数据库
    if [ -f "/var/lib/acornfox/data/acornfox.db" ]; then
        cp /var/lib/acornfox/data/acornfox.db "${BACKUP_PATH}/acornfox.db" || error_exit "备份数据库失败"
        log_success "数据库已备份"
    fi

    # 记录版本信息
    echo "$CURRENT_VERSION" > "${BACKUP_PATH}/version.txt"

    log_success "备份完成: $BACKUP_PATH"
    echo "$BACKUP_PATH" > /tmp/acornfox_last_backup
}

# 下载新版本
download_new_version() {
    log_info "下载新版本..."

    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64) ARCH="amd64" ;;
        aarch64) ARCH="arm64" ;;
        *) error_exit "不支持的架构: $ARCH" ;;
    esac

    VERSION="${1:-latest}"
    DOWNLOAD_URL="https://github.com/acornfox/acornfox/releases/download/${VERSION}/acornfox_linux_${ARCH}"

    # 检查是否在中国
    if curl -s -m 2 "http://ip-api.com/json/?fields=countryCode" 2>/dev/null | grep -q '"countryCode":"CN"'; then
        DOWNLOAD_URL="https://ghproxy.com/${DOWNLOAD_URL}"
        log_info "使用中国镜像"
    fi

    wget -q --show-progress "$DOWNLOAD_URL" -O /tmp/acornfox.new || error_exit "下载失败"
    chmod +x /tmp/acornfox.new

    # 验证新版本
    NEW_VERSION=$(/tmp/acornfox.new version 2>/dev/null | awk '{print $2}' || echo "unknown")
    log_info "新版本: $NEW_VERSION"

    if [ "$NEW_VERSION" = "$CURRENT_VERSION" ]; then
        log_warn "新版本与当前版本相同"
        read -p "是否继续? (y/N) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            rm -f /tmp/acornfox.new
            exit 0
        fi
    fi
}

# 停止服务
stop_services() {
    log_info "停止服务..."

    systemctl stop acornfox-server || log_warn "停止 acornfox-server 失败"
    systemctl stop acornfox-runner || log_warn "停止 acornfox-runner 失败"

    # 等待服务完全停止
    sleep 2

    log_success "服务已停止"
}

# 执行数据库迁移
run_migrations() {
    log_info "执行数据库迁移..."

    # 使用新版本的 acornfox 执行迁移
    su - acornfox -c "/tmp/acornfox.new migrate" || {
        log_error "数据库迁移失败"
        return 1
    }

    log_success "数据库迁移完成"
    return 0
}

# 替换二进制文件
replace_binary() {
    log_info "替换二进制文件..."

    mv /tmp/acornfox.new /usr/local/bin/acornfox || error_exit "替换失败"
    chown root:root /usr/local/bin/acornfox
    chmod 755 /usr/local/bin/acornfox

    log_success "二进制文件已更新"
}

# 启动服务
start_services() {
    log_info "启动服务..."

    systemctl start acornfox-runner
    sleep 2
    systemctl start acornfox-server
    sleep 3

    # 检查服务状态
    if systemctl is-active --quiet acornfox-server && systemctl is-active --quiet acornfox-runner; then
        log_success "服务启动成功"
        return 0
    else
        log_error "服务启动失败"
        return 1
    fi
}

# 验证升级
verify_upgrade() {
    log_info "验证升级..."

    # 检查版本
    INSTALLED_VERSION=$(/usr/local/bin/acornfox version 2>/dev/null | awk '{print $2}' || echo "unknown")
    log_info "已安装版本: $INSTALLED_VERSION"

    # 检查服务状态
    if systemctl is-active --quiet acornfox-server && systemctl is-active --quiet acornfox-runner; then
        log_success "升级验证通过"
        return 0
    else
        log_error "服务运行异常"
        return 1
    fi
}

# 回滚
rollback() {
    log_warn "开始回滚..."

    BACKUP_PATH=$(cat /tmp/acornfox_last_backup 2>/dev/null || echo "")

    if [ -z "$BACKUP_PATH" ] || [ ! -d "$BACKUP_PATH" ]; then
        error_exit "找不到备份，无法回滚"
    fi

    # 停止服务
    systemctl stop acornfox-server acornfox-runner || true

    # 恢复二进制文件
    if [ -f "${BACKUP_PATH}/acornfox.bin" ]; then
        cp "${BACKUP_PATH}/acornfox.bin" /usr/local/bin/acornfox
        chmod 755 /usr/local/bin/acornfox
        log_success "二进制文件已恢复"
    fi

    # 恢复数据库
    if [ -f "${BACKUP_PATH}/acornfox.db" ]; then
        cp "${BACKUP_PATH}/acornfox.db" /var/lib/acornfox/data/acornfox.db
        chown acornfox:acornfox /var/lib/acornfox/data/acornfox.db
        chmod 600 /var/lib/acornfox/data/acornfox.db
        log_success "数据库已恢复"
    fi

    # 启动服务
    systemctl start acornfox-runner
    sleep 2
    systemctl start acornfox-server
    sleep 3

    if systemctl is-active --quiet acornfox-server && systemctl is-active --quiet acornfox-runner; then
        log_success "回滚完成，服务已恢复"
    else
        error_exit "回滚后服务启动失败，请检查日志"
    fi
}

# 清理旧备份（保留最近 5 个）
cleanup_old_backups() {
    BACKUP_DIR="/var/lib/acornfox/backups"

    if [ -d "$BACKUP_DIR" ]; then
        BACKUP_COUNT=$(ls -1 "$BACKUP_DIR" | wc -l)

        if [ "$BACKUP_COUNT" -gt 5 ]; then
            log_info "清理旧备份..."
            ls -1t "$BACKUP_DIR" | tail -n +6 | xargs -I {} rm -rf "${BACKUP_DIR}/{}"
            log_success "已清理旧备份"
        fi
    fi
}

# 检查应用容器状态
check_apps() {
    log_info "检查应用容器状态..."

    APP_COUNT=$(docker ps --filter "label=acornfox.app" --format "{{.Names}}" 2>/dev/null | wc -l || echo "0")

    if [ "$APP_COUNT" -gt 0 ]; then
        log_success "应用容器运行正常 ($APP_COUNT 个容器)"
    else
        log_info "当前没有运行中的应用"
    fi
}

# 显示升级摘要
show_summary() {
    NEW_VERSION=$(/usr/local/bin/acornfox version 2>/dev/null | awk '{print $2}' || echo "unknown")

    cat << EOF

${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}
${GREEN}✓ 升级完成！${NC}
${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}

${BLUE}版本:${NC}
  • 升级前: $CURRENT_VERSION
  • 升级后: $NEW_VERSION

${BLUE}服务状态:${NC}
  • acornfox-server: $(systemctl is-active acornfox-server)
  • acornfox-runner: $(systemctl is-active acornfox-runner)

${BLUE}备份位置:${NC}
  $(cat /tmp/acornfox_last_backup)

${BLUE}如需回滚:${NC}
  ${YELLOW}sudo bash upgrade.sh --rollback${NC}

${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}

EOF
}

# 主函数
main() {
    echo ""
    log_info "AcornFox 升级脚本"
    echo ""

    # 处理回滚请求
    if [ "${1:-}" = "--rollback" ]; then
        check_root
        rollback
        exit 0
    fi

    check_root
    check_installed

    # 确认升级
    echo ""
    read -p "确认升级 AcornFox? (y/N) " -n 1 -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_info "取消升级"
        exit 0
    fi

    # 升级流程
    backup_current
    download_new_version "${1:-latest}"
    stop_services

    # 尝试执行迁移
    if ! run_migrations; then
        log_error "迁移失败，开始回滚..."
        rollback
        error_exit "升级失败，已回滚到原版本"
    fi

    replace_binary

    # 尝试启动服务
    if ! start_services; then
        log_error "服务启动失败，开始回滚..."
        rollback
        error_exit "升级失败，已回滚到原版本"
    fi

    # 验证升级
    if ! verify_upgrade; then
        log_warn "升级验证失败，建议检查日志"
    fi

    # 检查应用
    check_apps

    # 清理
    cleanup_old_backups

    # 显示摘要
    show_summary
}

main "$@"
