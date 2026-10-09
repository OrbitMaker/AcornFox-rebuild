#!/usr/bin/env bash
# AcornFox 安装脚本
# 用途: 在干净的 Linux 系统上一键安装 AcornFox
# 支持: Ubuntu 24.04/22.04/20.04, Debian 12/11
# 许可: AGPL-3.0

set -euo pipefail

# curl | sudo bash 时 stdin 是脚本本身，不能让 apt/debconf 交互读取它
export DEBIAN_FRONTEND=noninteractive

# 新开的云主机开机后 unattended-upgrades 会占用 dpkg 锁几分钟，等锁释放而不是直接失败
apt_get() {
    apt-get -o DPkg::Lock::Timeout=600 -o Acquire::Retries=3 "$@"
}

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

# GitHub 仓库与下载代理
# ACORNFOX_REPO 可覆盖发布仓库；ACORNFOX_GITHUB_PROXY 指定自己的 GitHub 加速前缀
# （形如 https://example.com/，拼接为 前缀+原始地址）。中国大陆先直连，失败再依次试代理。
ACORNFOX_REPO="${ACORNFOX_REPO:-OrbitMaker/AcornFox-rebuild}"
GITHUB_PROXIES=()

setup_github_proxies() {
    GITHUB_PROXIES=("")
    if [ -n "${ACORNFOX_GITHUB_PROXY:-}" ]; then
        GITHUB_PROXIES+=("${ACORNFOX_GITHUB_PROXY%/}/")
    fi
    if $IN_CHINA; then
        GITHUB_PROXIES+=("https://ghfast.top/" "https://gh-proxy.com/")
    fi
}

# github_download URL OUT：依次直连、走代理下载 GitHub 文件
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

# github_latest_tag：通过 releases/latest 的跳转地址取最新版本号（不依赖 api.github.com）
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
                log_warn "未测试的 Ubuntu 版本: ${OS_VERSION}，继续安装可能遇到问题"
            fi
            ;;
        debian)
            if [[ ! "$OS_VERSION" =~ ^(11|12)$ ]]; then
                log_warn "未测试的 Debian 版本: ${OS_VERSION}，继续安装可能遇到问题"
            fi
            ;;
        *)
            error_exit "不支持的操作系统: ${OS}，目前仅支持 Ubuntu 和 Debian"
            ;;
    esac
}

# 检测地理位置（判断是否在中国大陆）
detect_location() {
    log_info "检测服务器地理位置..."

    IN_CHINA=false
    CLOUD=""

    # 方法 1: 检查云厂商元数据（同时记下云厂商，用来优先选它的内网软件源）
    # 阿里云
    if curl -s -m 2 http://100.100.100.200/latest/meta-data/region-id 2>/dev/null | grep -q "cn-"; then
        IN_CHINA=true
        CLOUD=aliyun
        log_info "检测到阿里云中国区域"
        return
    fi

    # 腾讯云
    if curl -s -m 2 http://metadata.tencentyun.com/latest/meta-data/placement/region 2>/dev/null | grep -q "ap-"; then
        if curl -s -m 2 http://metadata.tencentyun.com/latest/meta-data/placement/region 2>/dev/null | grep -qE "ap-beijing|ap-shanghai|ap-guangzhou|ap-chengdu|ap-chongqing"; then
            IN_CHINA=true
            CLOUD=tencent
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
    ACORNFOX_VERSION="latest"
    LOCAL_BINARY=""
    REGISTRY_MIRRORS=()
    PUBLIC_HOST=""

    while [[ $# -gt 0 ]]; do
        case $1 in
            --version)
                [[ $# -ge 2 ]] || error_exit "--version 需要一个版本号，例如 v0.2.0"
                ACORNFOX_VERSION="$2"
                shift 2
                ;;
            --binary)
                [[ $# -ge 2 ]] || error_exit "--binary 需要一个本地文件路径"
                LOCAL_BINARY="$2"
                shift 2
                ;;
            --public-host)
                [[ $# -ge 2 ]] || error_exit "--public-host 需要服务器的公网 IP 或域名"
                PUBLIC_HOST="$2"
                shift 2
                ;;
            --registry-mirror)
                [[ $# -ge 2 ]] || error_exit "--registry-mirror 需要一个地址，例如 https://xxxx.mirror.aliyuncs.com"
                REGISTRY_MIRRORS+=("$2")
                shift 2
                ;;
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
    --version V            安装指定版本（默认 latest）
    --binary PATH          使用本地 acornfox 二进制文件，不下载（用于测试候选版本）
    --public-host HOST     应用访问地址中的主机（公网 IP 或域名），默认自动检测
    --registry-mirror URL  Docker Hub 镜像加速地址，可重复指定
                           阿里云 ECS 建议使用控制台“容器镜像服务 → 镜像加速器”中的专属地址
    --china                强制使用中国镜像源
    --global               强制使用国际源
    --skip-docker          跳过 Docker 安装（如已安装）
    --skip-caddy           跳过 Caddy 安装（如已安装）
    -h, --help             显示此帮助信息

环境变量:
    ACORNFOX_GITHUB_PROXY  GitHub 下载加速前缀，如 https://ghfast.top/（直连失败时使用）
    ACORNFOX_REPO          发布仓库，默认 acornfox/acornfox

示例:
    # 自动检测并安装
    sudo bash install.sh

    # 强制使用中国镜像源，并指定阿里云专属镜像加速
    sudo bash install.sh --china --registry-mirror https://xxxx.mirror.aliyuncs.com

    # 跳过已安装的 Docker
    sudo bash install.sh --skip-docker

EOF
}

# 更新软件包列表
update_apt() {
    log_info "更新软件包列表..."

    # 中国大陆只在软件源指向境外官方地址时才替换。云厂商镜像自带的内网源（如阿里云
    # mirrors.cloud.aliyuncs.com）走内网，冷启动 apt update 实测 17 秒，换成公网
    # mirrors.aliyun.com 要 251 秒，所以其他任何源都原样保留。
    local official='//(archive|security|ports)\.ubuntu\.com|//(deb|security)\.debian\.org'
    if $IN_CHINA && grep -rqsE "$official" /etc/apt/sources.list /etc/apt/sources.list.d/; then
        log_info "配置 APT 使用国内镜像..."
        case "$OS" in
            ubuntu)
                cp /etc/apt/sources.list /etc/apt/sources.list.bak 2>/dev/null || true
                cat > /etc/apt/sources.list << EOF
deb http://mirrors.aliyun.com/ubuntu/ ${OS_CODENAME} main restricted universe multiverse
deb http://mirrors.aliyun.com/ubuntu/ ${OS_CODENAME}-updates main restricted universe multiverse
deb http://mirrors.aliyun.com/ubuntu/ ${OS_CODENAME}-backports main restricted universe multiverse
deb http://mirrors.aliyun.com/ubuntu/ ${OS_CODENAME}-security main restricted universe multiverse
EOF
                ;;
            debian)
                cp /etc/apt/sources.list /etc/apt/sources.list.bak 2>/dev/null || true
                cat > /etc/apt/sources.list << EOF
deb http://mirrors.aliyun.com/debian/ ${OS_CODENAME} main contrib non-free
deb http://mirrors.aliyun.com/debian/ ${OS_CODENAME}-updates main contrib non-free
deb http://mirrors.aliyun.com/debian-security ${OS_CODENAME}-security main contrib non-free
EOF
                ;;
        esac
        # Ubuntu 24.04 / Debian 12 的默认源在 deb822 格式的 *.sources 里，指向官方地址的
        # 一并停用，否则境外源仍会参与 update
        local f
        for f in /etc/apt/sources.list.d/*.sources; do
            [ -f "$f" ] || continue
            if grep -qE "$official" "$f"; then
                mv "$f" "$f.bak"
                log_info "已停用境外官方源 ${f}（备份为 $f.bak）"
            fi
        done
    elif $IN_CHINA; then
        log_info "APT 已使用非官方境外源（云厂商内网源或国内镜像），保持不变"
    fi

    apt_get update -qq || error_exit "更新软件包列表失败"
}

# 安装基础依赖
install_dependencies() {
    log_info "安装基础依赖..."
    apt_get install -y -qq \
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

    # 国内镜像站在 Docker 新版本发布后会有一段时间不一致（索引大小不符、包 404、读超时），
    # 依次换源；全部失败时退回发行版仓库自带的 docker.io。
    # 每项是 "软件包地址|GPG 密钥地址"。云厂商内网源只有 http，签名密钥仍从 https 获取，
    # 包的真实性由签名保证。
    local sources=() entry src gpg attempt installed=false
    if $IN_CHINA; then
        case "${CLOUD:-}" in
            aliyun) sources+=("http://mirrors.cloud.aliyuncs.com/docker-ce|https://mirrors.aliyun.com/docker-ce") ;;
            tencent) sources+=("http://mirrors.tencentyun.com/docker-ce|https://mirrors.cloud.tencent.com/docker-ce") ;;
        esac
        sources+=("https://mirrors.aliyun.com/docker-ce|https://mirrors.aliyun.com/docker-ce"
                  "https://mirrors.cloud.tencent.com/docker-ce|https://mirrors.cloud.tencent.com/docker-ce"
                  "https://mirrors.tuna.tsinghua.edu.cn/docker-ce|https://mirrors.tuna.tsinghua.edu.cn/docker-ce")
    else
        sources=("https://download.docker.com|https://download.docker.com")
    fi

    for entry in "${sources[@]}"; do
        src="${entry%%|*}"
        gpg="${entry##*|}"
        log_info "使用 Docker 源: ${src}"
        if ! curl -fsSL --connect-timeout 10 --max-time 60 "${gpg}/linux/${OS}/gpg" \
            | gpg --batch --yes --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg; then
            log_warn "无法从 ${gpg} 获取 GPG 密钥，换下一个源"
            continue
        fi
        echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] ${src}/linux/${OS} ${OS_CODENAME} stable" > /etc/apt/sources.list.d/docker.list
        # 索引不一致（镜像站同步中）时 update 就会失败，重试同一个源也没用，直接换源；
        # update 成功但下载包失败多半是偶发，再试一次
        if ! apt_get update -qq; then
            log_warn "Docker 源 ${src} 索引不可用（镜像站可能正在同步），换下一个源"
            continue
        fi
        for attempt in 1 2; do
            if apt_get install -y -qq docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin; then
                installed=true
                break 2
            fi
            log_warn "从 ${src} 安装 Docker 第 ${attempt} 次失败"
            sleep 3
        done
    done

    if ! $installed; then
        # 不留下失效的源，免得之后的 apt-get update 一直报错
        rm -f /etc/apt/sources.list.d/docker.list
        log_warn "Docker 官方源均不可用，改用发行版仓库的 docker.io"
        apt_get update -qq || true
        apt_get install -y -qq docker.io \
            || error_exit "Docker 安装失败：所有 Docker 源都不可用，请稍后重试，或先手动安装 Docker 后用 --skip-docker"
        # runner 通过 Docker API 构建，不依赖 buildx；Debian 11/12 仓库没有这个包，装不上不算失败
        apt_get install -y -qq docker-buildx >/dev/null 2>&1 || true
    fi

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

    if [ ${#REGISTRY_MIRRORS[@]} -eq 0 ]; then
        if ! $IN_CHINA; then
            log_info "非中国环境，跳过镜像加速配置"
            return
        fi
        # 公共加速器可用性经常变化；阿里云 ECS 用户应改用控制台里的专属地址
        REGISTRY_MIRRORS=("https://docker.m.daocloud.io" "https://mirror.ccs.tencentyun.com")
    fi

    # 已有 daemon.json 时不覆盖，避免破坏用户已有的 Docker 配置
    if [ -s /etc/docker/daemon.json ]; then
        if grep -q '"registry-mirrors"' /etc/docker/daemon.json; then
            log_info "/etc/docker/daemon.json 已配置 registry-mirrors，保持不变"
        else
            log_warn "/etc/docker/daemon.json 已存在，未自动修改；如需镜像加速，请手动加入："
            echo "    \"registry-mirrors\": [$(printf '"%s",' "${REGISTRY_MIRRORS[@]}" | sed 's/,$//')]"
        fi
        return
    fi

    mkdir -p /etc/docker
    cat > /etc/docker/daemon.json << EOF
{
  "registry-mirrors": [$(printf '"%s",' "${REGISTRY_MIRRORS[@]}" | sed 's/,$//')],
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  }
}
EOF

    systemctl daemon-reload
    systemctl restart docker

    log_success "Docker 镜像加速配置完成: ${REGISTRY_MIRRORS[*]}"
    log_info "阿里云 ECS 建议改用专属加速地址：容器镜像服务控制台 → 镜像工具 → 镜像加速器"
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
        # apt 源 dl.cloudsmith.io 在大陆不稳定，国内镜像站也没有同步它；Ubuntu/Debian 仓库里的
        # caddy 2.6.2 不支持 persist_config。所以下载官方二进制：AcornFox 发行版在 Gitee 上附带
        # 同一份 Caddy 安装包与官方校验文件，先从 Gitee 取，失败再走 GitHub 直连和代理。
        ARCH=$(dpkg --print-architecture)
        CADDY_VERSION="2.8.4"
        local caddy_tag="" name
        if [ -n "$ACORNFOX_GITEE_REPO" ]; then
            caddy_tag="$ACORNFOX_VERSION"
            [ "$caddy_tag" = "latest" ] && caddy_tag=$(latest_tag 2>/dev/null || true)
        fi
        local official="https://github.com/caddyserver/caddy/releases/download/v${CADDY_VERSION}"
        local mirror="https://gitee.com/${ACORNFOX_GITEE_REPO}/releases/download/${caddy_tag}"
        name="caddy_${CADDY_VERSION}_linux_${ARCH}.tar.gz"
        if [ -n "$caddy_tag" ] && curl -fL --connect-timeout 10 --max-time 600 --speed-limit 51200 --speed-time 15 \
            -o "/tmp/${name}" "${mirror}/${name}"; then
            log_info "已从 Gitee 镜像下载 ${name}"
        else
            log_info "从 GitHub 下载 ${name}..."
            github_download "${official}/${name}" "/tmp/${name}" \
                || error_exit "下载 Caddy 失败；可设置 ACORNFOX_GITHUB_PROXY 指定可用的 GitHub 加速地址后重试"
        fi
        # 校验文件只有几 KB，优先取 Caddy 官方的，与镜像上的安装包互相独立；取不到再用镜像副本
        name="caddy_${CADDY_VERSION}_checksums.txt"
        if ! curl -fsSL --connect-timeout 10 --max-time 30 -o "/tmp/${name}" "${official}/${name}"; then
            if [ -n "$caddy_tag" ] && curl -fsSL --connect-timeout 10 --max-time 60 -o "/tmp/${name}" "${mirror}/${name}"; then
                log_warn "Caddy 官方校验文件取不到，改用 Gitee 镜像上的副本"
            else
                github_download "${official}/${name}" "/tmp/${name}" || error_exit "下载 Caddy 校验文件失败"
            fi
        fi
        mv "/tmp/caddy_${CADDY_VERSION}_linux_${ARCH}.tar.gz" /tmp/caddy.tar.gz
        mv "/tmp/caddy_${CADDY_VERSION}_checksums.txt" /tmp/caddy_checksums.txt

        # 无论从哪里下载，都按 Caddy 官方发布的 SHA-512 校验
        CADDY_WANT=$(awk -v a="caddy_${CADDY_VERSION}_linux_${ARCH}.tar.gz" '$2 == a {print $1; exit}' /tmp/caddy_checksums.txt)
        rm -f /tmp/caddy_checksums.txt
        if [ -z "$CADDY_WANT" ] || [ "$(sha512sum /tmp/caddy.tar.gz | awk '{print $1}')" != "$CADDY_WANT" ]; then
            rm -f /tmp/caddy.tar.gz
            error_exit "Caddy 安装包 SHA-512 校验失败"
        fi

        tar -xzf /tmp/caddy.tar.gz -C /tmp caddy
        install -m 0755 /tmp/caddy /usr/bin/caddy
        rm -f /tmp/caddy.tar.gz /tmp/caddy

        # 二进制安装没有 deb 包自带的账号和 systemd 服务，这里补齐
        if ! getent group caddy >/dev/null; then
            groupadd --system caddy
        fi
        if ! id caddy >/dev/null 2>&1; then
            useradd --system --gid caddy --create-home --home-dir /var/lib/caddy \
                --shell /usr/sbin/nologin --comment "Caddy web server" caddy
        fi
        cat > /etc/systemd/system/caddy.service << 'EOF'
[Unit]
Description=Caddy
Documentation=https://caddyserver.com/docs/
After=network.target network-online.target
Requires=network-online.target

[Service]
Type=notify
User=caddy
Group=caddy
ExecStart=/usr/bin/caddy run --environ --config /etc/caddy/Caddyfile
ExecReload=/usr/bin/caddy reload --config /etc/caddy/Caddyfile --force
TimeoutStopSec=5s
LimitNOFILE=1048576
PrivateTmp=true
ProtectSystem=full
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl enable caddy
    else
        # 使用官方 apt 仓库安装
        log_info "使用官方仓库安装 Caddy..."

        # 添加 Caddy GPG 密钥
        curl -fsSL https://dl.cloudsmith.io/public/caddy/stable/gpg.key | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg

        # 添加 Caddy 仓库
        echo "deb [signed-by=/usr/share/keyrings/caddy-stable-archive-keyring.gpg] https://dl.cloudsmith.io/public/caddy/stable/deb/debian any-version main" | tee /etc/apt/sources.list.d/caddy-stable.list

        # 安装 Caddy
        apt_get update -qq
        apt_get install -y -qq caddy || error_exit "Caddy 安装失败"
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
    # socket 由 Caddy 以 0660 创建；/run/acornfox 是 setgid 目录，
    # socket 自动归属 acornfox-ipc 组，server 可直接访问，重启后无需再手动 chmod
    cat > /etc/caddy/Caddyfile << 'EOF'
{
    # AcornFox 以 http://caddy 访问管理接口，Caddy 校验 Host 头；
    # origins 不支持通配符，写 * 会拒绝所有请求（403 host not allowed: caddy）
    admin unix//run/acornfox/caddy-admin.sock|0660 {
        origins caddy
    }
    persist_config off
}

# AcornFox 应用路由将通过 API 动态添加
EOF

    chown root:root /etc/caddy/Caddyfile
    chmod 644 /etc/caddy/Caddyfile

    # 组成员变化（caddy 加入 acornfox-ipc）需要重启才生效
    systemctl enable caddy
    systemctl restart caddy

    local i
    for i in $(seq 1 10); do
        [ -S /run/acornfox/caddy-admin.sock ] && break
        sleep 1
    done
    if [ -S /run/acornfox/caddy-admin.sock ]; then
        log_success "Caddy admin socket 配置完成"
    else
        error_exit "Caddy admin socket 未创建，请检查: journalctl -u caddy -n 50"
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

    # 已存在的账号也确保在 acornfox-ipc 组中（重复安装、旧版本升级）
    usermod -aG acornfox-ipc acornfox
    usermod -aG acornfox-ipc acornfox-exec

    # caddy 需要在 /run/acornfox 中创建 admin socket
    if id caddy >/dev/null 2>&1; then
        usermod -aG acornfox-ipc caddy
        log_info "已将 caddy 用户添加到 acornfox-ipc 组"
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

    if [ -n "$LOCAL_BINARY" ]; then
        [ -f "$LOCAL_BINARY" ] || error_exit "本地二进制文件不存在: $LOCAL_BINARY"
        log_info "使用本地二进制文件: $LOCAL_BINARY"
        install -m 0755 "$LOCAL_BINARY" /usr/local/bin/acornfox.new
        mv -f /usr/local/bin/acornfox.new /usr/local/bin/acornfox
        log_success "AcornFox 安装成功: $(/usr/local/bin/acornfox version)"
        return
    fi

    # 从 GitHub Releases 下载
    # 格式: https://github.com/<repo>/releases/download/v0.2.0/acornfox_linux_amd64
    VERSION="$ACORNFOX_VERSION"

    if [ "$VERSION" = "latest" ]; then
        log_info "获取最新版本号..."
        VERSION=$(latest_tag) || error_exit "无法获取最新版本号；用 --version vX.Y.Z 指定版本，或用 --binary 安装本地文件"
        log_info "最新版本: $VERSION"
    fi

    log_info "下载 AcornFox ${VERSION}（acornfox_linux_${ARCH}）"

    if release_download "$VERSION" "acornfox_linux_${ARCH}" /tmp/acornfox; then
        log_success "下载完成"
    else
        error_exit "下载 AcornFox 失败，请检查网络或版本号；也可设置 ACORNFOX_GITHUB_PROXY 或使用 --binary"
    fi
    verify_sha256 /tmp/acornfox "acornfox_linux_${ARCH}" "$VERSION"

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

    # 数据目录：数据库只有 acornfox 可读；runner（acornfox-exec）只需穿过
    # /var/lib/acornfox 去读 uploads/ 中的上传包，所以组只给执行权限
    mkdir -p /var/lib/acornfox/uploads
    chown acornfox:acornfox-ipc /var/lib/acornfox
    chmod 0710 /var/lib/acornfox
    chown acornfox:acornfox-ipc /var/lib/acornfox/uploads
    chmod 2750 /var/lib/acornfox/uploads

    # /run 是 tmpfs，重启后会清空；用 tmpfiles.d 让 systemd 每次开机重建。
    # setgid 让 server、runner、caddy 各自创建的 socket 都归属 acornfox-ipc 组。
    # 其他用户只有穿过权限（o+x），能否连接由各 socket 自身决定：
    # api.sock 归 acornfox-users 组（CLI 用户），caddy-admin.sock 只给 acornfox-ipc。
    cat > /etc/tmpfiles.d/acornfox.conf << 'EOF'
d /run/acornfox 2771 root acornfox-ipc -
EOF
    systemd-tmpfiles --create /etc/tmpfiles.d/acornfox.conf
    # 旧版本安装可能留下其他属主，统一修正
    chown root:acornfox-ipc /run/acornfox
    chmod 2771 /run/acornfox

    log_success "数据目录创建完成"
}

# 初始化数据库
initialize_database() {
    log_info "初始化数据库..."

    # 使用 acornfox 用户初始化数据库
    su - acornfox -c "/usr/local/bin/acornfox init" || error_exit "数据库初始化失败"

    # 设置数据库文件权限（路径与 server 的 --data-dir 默认值一致）
    chmod 600 /var/lib/acornfox/acornfox.db

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

# 检测应用访问地址中的主机：优先云厂商元数据里的公网 IP，取不到再用本机首个地址。
# 元数据接口出错时会返回 HTML 页面，所以每个结果都要校验是 IPv4。
detect_public_host() {
    if [ -n "$PUBLIC_HOST" ]; then
        log_info "应用访问地址主机: ${PUBLIC_HOST}（手动指定）"
        return
    fi
    local url ip
    for url in \
        http://100.100.100.200/latest/meta-data/eipv4 \
        http://100.100.100.200/latest/meta-data/public-ipv4 \
        http://metadata.tencentyun.com/latest/meta-data/public-ipv4 \
        http://169.254.169.254/latest/meta-data/public-ipv4; do
        ip=$(curl -fs -m 2 "$url" 2>/dev/null || true)
        if [[ "$ip" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
            PUBLIC_HOST="$ip"
            log_info "应用访问地址主机: ${PUBLIC_HOST}（云厂商元数据）"
            return
        fi
    done
    PUBLIC_HOST=$(hostname -I 2>/dev/null | awk '{print $1}')
    if [ -n "$PUBLIC_HOST" ]; then
        log_warn "未从云厂商元数据取到公网 IP，暂用本机地址 ${PUBLIC_HOST}；如不对，用 --public-host 重新安装或修改 acornfox-server 服务"
    else
        log_warn "无法确定服务器地址，部署输出的访问地址将不含主机名；可用 --public-host 指定"
    fi
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
Documentation=https://github.com/OrbitMaker/AcornFox-rebuild
After=network.target docker.service
Requires=docker.service

[Service]
Type=simple
User=acornfox
Group=acornfox
ExecStart=/usr/local/bin/acornfox server --runner-uid $ACORNFOX_EXEC_UID --listen-group acornfox-users${PUBLIC_HOST:+ --public-host $PUBLIC_HOST}
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
Documentation=https://github.com/OrbitMaker/AcornFox-rebuild
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
    # 用 restart：重复安装时让已运行的服务换上新二进制和新组成员
    systemctl enable acornfox-server acornfox-runner
    systemctl restart acornfox-runner
    sleep 2
    systemctl restart acornfox-server

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

${BLUE}云服务器安全组（重要）:${NC}
  应用通过 ${YELLOW}http://${PUBLIC_HOST:-服务器IP}:端口${NC} 访问，端口在 18810-18899 之间分配。
  请在云厂商控制台的安全组中放行入方向 TCP ${YELLOW}18810-18899${NC}；
  绑定域名并启用 HTTPS 还需要放行 ${YELLOW}80${NC} 和 ${YELLOW}443${NC}。

${BLUE}下一步:${NC}
  1. 在本地电脑安装 CLI:
     ${YELLOW}curl -fsSL https://github.com/OrbitMaker/AcornFox-rebuild/releases/latest/download/install-cli.sh | bash${NC}

  2. 配置服务器连接（SSH 用户需为 root 或在 acornfox-users 组中）:
     ${YELLOW}sudo usermod -aG acornfox-users <你的 SSH 用户>${NC}   # 非 root 时执行一次
     ${YELLOW}acornfox target add my-server --ssh user@${HOSTNAME}${NC}

  3. 打开网页控制台:
     ${YELLOW}acornfox open${NC}

${BLUE}文档:${NC}
  https://github.com/OrbitMaker/AcornFox-rebuild/tree/main/docs

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
    echo ""

    # --help 不需要 root，也不做环境探测
    local arg
    for arg in "$@"; do
        case "$arg" in
            -h|--help) show_help; exit 0 ;;
        esac
    done

    # 检查权限
    check_root

    # 检测环境
    detect_os
    detect_location

    # 解析参数
    parse_args "$@"
    setup_github_proxies
    # 记下网络环境判断，upgrade.sh 直接沿用，不必再依赖外部 IP 查询
    mkdir -p /etc/acornfox
    echo "ACORNFOX_IN_CHINA=${IN_CHINA}" > /etc/acornfox/install.env

    # 安装流程
    update_apt
    install_dependencies
    install_docker
    configure_docker_mirror
    install_caddy
    create_accounts
    create_directories
    configure_caddy
    download_acornfox
    initialize_database
    generate_admin_token
    detect_public_host
    create_systemd_services
    start_services

    # 显示摘要
    show_summary
}

# 执行主函数
main "$@"
