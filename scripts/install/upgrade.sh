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

# 与 server --data-dir 默认值一致
DB_PATH="/var/lib/acornfox/acornfox.db"
ASSUME_YES=false
TARGET_VERSION="latest"
LOCAL_BINARY=""
DO_ROLLBACK=false

parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -y|--yes) ASSUME_YES=true; shift ;;
            --rollback) DO_ROLLBACK=true; shift ;;
            --version)
                [[ $# -ge 2 ]] || error_exit "--version 需要一个版本号"
                TARGET_VERSION="$2"; shift 2 ;;
            --binary)
                [[ $# -ge 2 ]] || error_exit "--binary 需要一个本地文件路径"
                LOCAL_BINARY="$2"; shift 2 ;;
            *) error_exit "未知参数: $1（可用：-y、--version V、--binary PATH、--rollback）" ;;
        esac
    done
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
    # 安装时已判断过网络环境并记在 install.env；旧版本安装没有这个文件时再探测
    IN_CHINA=false
    if [ -r /etc/acornfox/install.env ]; then
        grep -qx 'ACORNFOX_IN_CHINA=true' /etc/acornfox/install.env && IN_CHINA=true
    elif detect_china; then
        IN_CHINA=true
    fi
    if $IN_CHINA; then
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
        if curl -fL --connect-timeout 10 --max-time 600 --speed-limit 51200 --speed-time 15 -o "$out" "${p}${url}"; then
            return 0
        fi
    done
    log_info "所有下载源都较慢，不限速重试一次"
    curl -fL --connect-timeout 10 --max-time 1800 --retry 2 -o "$out" "${GITHUB_PROXIES[0]}${url}"
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

confirm() {
    $ASSUME_YES && return 0
    [ -t 0 ] || error_exit "非交互环境请加 -y 确认"
    read -p "$1 (y/N) " -n 1 -r
    echo
    [[ $REPLY =~ ^[Yy]$ ]]
}

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

    # 备份数据库（服务已停止，连同 WAL 文件一起复制才是一致的快照）
    [ -f "$DB_PATH" ] || error_exit "找不到数据库 ${DB_PATH}，拒绝在没有备份的情况下升级"
    local f
    for f in "$DB_PATH" "$DB_PATH-wal" "$DB_PATH-shm"; do
        if [ -f "$f" ]; then
            cp -p "$f" "${BACKUP_PATH}/$(basename "$f")" || error_exit "备份数据库失败: $f"
        fi
    done
    log_success "数据库已备份"

    # 记录版本信息
    echo "$CURRENT_VERSION" > "${BACKUP_PATH}/version.txt"

    log_success "备份完成: $BACKUP_PATH"
    echo "$BACKUP_PATH" > /tmp/acornfox_last_backup
}

# 下载新版本
download_new_version() {
    if [ -n "$LOCAL_BINARY" ]; then
        [ -f "$LOCAL_BINARY" ] || error_exit "本地二进制文件不存在: $LOCAL_BINARY"
        install -m 0755 "$LOCAL_BINARY" /tmp/acornfox.new
        NEW_VERSION=$(/tmp/acornfox.new version 2>/dev/null | awk '{print $2}' || echo "unknown")
        log_info "使用本地二进制文件: ${LOCAL_BINARY}（${NEW_VERSION}）"
        return
    fi

    log_info "下载新版本..."

    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64) ARCH="amd64" ;;
        aarch64) ARCH="arm64" ;;
        *) error_exit "不支持的架构: $ARCH" ;;
    esac

    setup_github_proxies
    VERSION="$TARGET_VERSION"

    if [ "$VERSION" = "latest" ]; then
        log_info "获取最新版本号..."
        VERSION=$(latest_tag) || error_exit "无法获取最新版本号；用 --version vX.Y.Z 指定版本，或用 --binary 使用本地文件"
        log_info "最新版本: $VERSION"
    fi

    release_download "$VERSION" "acornfox_linux_${ARCH}" /tmp/acornfox.new \
        || error_exit "下载失败；可设置 ACORNFOX_GITHUB_PROXY 或使用 --binary"
    verify_sha256 /tmp/acornfox.new "acornfox_linux_${ARCH}" "$VERSION"
    chmod +x /tmp/acornfox.new

    # 验证新版本
    NEW_VERSION=$(/tmp/acornfox.new version 2>/dev/null | awk '{print $2}' || echo "unknown")
    log_info "新版本: $NEW_VERSION"

    if [ "$NEW_VERSION" = "$CURRENT_VERSION" ]; then
        log_warn "新版本与当前版本相同"
        if ! confirm "是否继续?"; then
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

# 旧版本安装的目录权限会让 runner 读不到上传包、重启后丢失 /run/acornfox，
# 这里补成与 install.sh 一致的布局（幂等）
fix_layout() {
    log_info "校正目录与组权限..."
    getent group acornfox-ipc >/dev/null || groupadd -r acornfox-ipc
    usermod -aG acornfox-ipc acornfox
    usermod -aG acornfox-ipc acornfox-exec
    if id caddy >/dev/null 2>&1; then
        usermod -aG acornfox-ipc caddy
    fi

    mkdir -p /var/lib/acornfox/uploads
    chown acornfox:acornfox-ipc /var/lib/acornfox /var/lib/acornfox/uploads
    chmod 0710 /var/lib/acornfox
    chmod 2750 /var/lib/acornfox/uploads

    echo 'd /run/acornfox 2771 root acornfox-ipc -' > /etc/tmpfiles.d/acornfox.conf
    systemd-tmpfiles --create /etc/tmpfiles.d/acornfox.conf
    chown root:acornfox-ipc /run/acornfox
    chmod 2771 /run/acornfox

    # api.sock 交给 acornfox-users 组（CLI 用户），不再要求 SSH 用户加入 acornfox-ipc
    getent group acornfox-users >/dev/null || groupadd -r acornfox-users
    local unit=/etc/systemd/system/acornfox-server.service
    if [ -f "$unit" ] && ! grep -q -- '--listen-group' "$unit"; then
        sed -i 's|^\(ExecStart=/usr/local/bin/acornfox server .*\)$|\1 --listen-group acornfox-users|' "$unit"
        systemctl daemon-reload
    fi
}

# 执行数据库迁移
run_migrations() {
    log_info "执行数据库迁移..."

    # 使用新版本的 acornfox 执行迁移
    su -s /bin/sh acornfox -c "/tmp/acornfox.new migrate --data-dir /var/lib/acornfox" || {
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

    # 恢复数据库：先删掉迁移后留下的 WAL，避免旧库叠上新 WAL
    if [ -f "${BACKUP_PATH}/acornfox.db" ]; then
        rm -f "$DB_PATH-wal" "$DB_PATH-shm"
        local f
        for f in acornfox.db acornfox.db-wal acornfox.db-shm; do
            if [ -f "${BACKUP_PATH}/$f" ]; then
                cp -p "${BACKUP_PATH}/$f" "/var/lib/acornfox/$f"
                chown acornfox:acornfox "/var/lib/acornfox/$f"
                chmod 600 "/var/lib/acornfox/$f"
            fi
        done
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

    parse_args "$@"

    if $DO_ROLLBACK; then
        check_root
        rollback
        exit 0
    fi

    check_root
    check_installed

    if ! confirm "确认升级 AcornFox?"; then
        log_info "取消升级"
        exit 0
    fi

    # 升级流程：先下载（失败不影响运行中的服务），再停服务、备份、迁移
    download_new_version
    stop_services
    backup_current
    fix_layout

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
