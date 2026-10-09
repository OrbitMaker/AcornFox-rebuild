#!/bin/bash
set -euo pipefail

# AcornFox 官网部署脚本
# 把仓库中已提交的 website/ 上传到服务器，由 Caddy 提供静态页面并自动申请 HTTPS 证书。
# 官网服务器与测试机分开，避免互相影响。服务器信息不写进仓库，通过环境变量传入。
# 用法: SERVER_IP=服务器地址 SSH_KEY=~/.ssh/xxx scripts/deploy-website.sh
#
# Caddy 配置只写官网自己的站点文件 /etc/caddy/sites/acornfox-website.caddy，
# 主 Caddyfile 只确保有 import 这一行，不覆盖服务器上已有的其他站点。

SERVER_IP="${SERVER_IP:?请用 SERVER_IP 指定官网服务器地址}"
SERVER_USER="${SERVER_USER:-root}"
DOMAIN="${DOMAIN:-acornfox.com}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

SSH_OPTS=(-o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new)
if [ -n "${SSH_KEY:-}" ]; then
    SSH_OPTS+=(-i "$SSH_KEY" -o IdentitiesOnly=yes)
fi
TARGET="${SERVER_USER}@${SERVER_IP}"

REV=$(git -C "$ROOT" rev-parse --short HEAD)
if [ -n "$(git -C "$ROOT" status --porcelain -- website)" ]; then
    echo "⚠️  website/ 有未提交的修改，本次只部署已提交的版本 ${REV}"
fi

echo "🚀 部署 AcornFox 官网（${REV}）"
echo "目标服务器: ${TARGET}"
echo "域名: ${DOMAIN}、www.${DOMAIN}"
echo ""

echo "📡 测试 SSH 连接..."
if ! ssh "${SSH_OPTS[@]}" "$TARGET" 'echo "✓ SSH 连接成功"'; then
    echo "❌ SSH 连接失败：检查服务器 IP、SSH 密钥（SSH_KEY）以及安全组是否放行 22"
    exit 1
fi

echo "📤 上传 website/（${REV}）..."
git -C "$ROOT" archive --format=tar HEAD website \
    | ssh "${SSH_OPTS[@]}" "$TARGET" 'rm -rf /tmp/acornfox-site && mkdir -p /tmp/acornfox-site && tar -x -C /tmp/acornfox-site'

echo ""
echo "📦 开始远程部署..."
ssh "${SSH_OPTS[@]}" "$TARGET" "DOMAIN='${DOMAIN}' REV='${REV}' bash -s" << 'ENDSSH'
set -e

echo "1️⃣ 更新系统包..."
apt-get update -qq

echo "2️⃣ 检查并安装 Caddy..."
if ! command -v caddy &> /dev/null; then
    # Caddy 官方 apt 仓库 dl.cloudsmith.io 现对匿名请求返回 402，改为下载官方二进制并按官方
    # SHA-512 校验；安装包先从 Gitee 镜像取（服务器在中国大陆），与 scripts/install/install.sh 一致。
    CADDY_VERSION=2.8.4
    ARCH=$(dpkg --print-architecture)
    NAME=caddy_${CADDY_VERSION}_linux_${ARCH}.tar.gz
    OFFICIAL=https://github.com/caddyserver/caddy/releases/download/v${CADDY_VERSION}
    MIRROR=https://gitee.com/VIP13390/AcornFox-rebuild/releases/download
    TAG=$(curl -fsS -m 15 https://gitee.com/api/v5/repos/VIP13390/AcornFox-rebuild/releases/latest 2>/dev/null \
        | grep -o '"tag_name":"[^"]*"' | head -1 | cut -d'"' -f4 || true)
    echo "   下载 Caddy ${CADDY_VERSION}..."
    if ! { [ -n "$TAG" ] && curl -fL --connect-timeout 10 --max-time 300 --speed-limit 51200 --speed-time 15 \
            -o "/tmp/${NAME}" "${MIRROR}/${TAG}/${NAME}"; }; then
        curl -fL --connect-timeout 10 --max-time 900 -o "/tmp/${NAME}" "${OFFICIAL}/${NAME}"
    fi
    curl -fsSL --max-time 60 -o /tmp/caddy_checksums.txt "${OFFICIAL}/caddy_${CADDY_VERSION}_checksums.txt" \
        || curl -fsSL --max-time 60 -o /tmp/caddy_checksums.txt "${MIRROR}/${TAG}/caddy_${CADDY_VERSION}_checksums.txt"
    WANT=$(awk -v a="$NAME" '$2 == a {print $1; exit}' /tmp/caddy_checksums.txt)
    if [ -z "$WANT" ] || [ "$(sha512sum "/tmp/${NAME}" | awk '{print $1}')" != "$WANT" ]; then
        echo "   ❌ Caddy 安装包 SHA-512 校验失败"
        exit 1
    fi
    tar -xzf "/tmp/${NAME}" -C /tmp caddy
    install -m 0755 /tmp/caddy /usr/bin/caddy
    rm -f "/tmp/${NAME}" /tmp/caddy /tmp/caddy_checksums.txt

    # 二进制安装没有 deb 包自带的账号、目录和 systemd 服务，这里补齐
    getent group caddy >/dev/null || groupadd --system caddy
    id caddy >/dev/null 2>&1 || useradd --system --gid caddy --create-home --home-dir /var/lib/caddy \
        --shell /usr/sbin/nologin --comment "Caddy web server" caddy
    mkdir -p /etc/caddy /var/log/caddy
    chown caddy:caddy /var/log/caddy
    cat > /etc/systemd/system/caddy.service << 'UNIT'
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
UNIT
    systemctl daemon-reload
    echo "   ✓ Caddy $(caddy version | awk '{print $1}') 已安装"
fi

echo "3️⃣ 部署官网文件..."
mkdir -p /var/www
rm -rf /var/www/acornfox.new
mv /tmp/acornfox-site/website /var/www/acornfox.new
echo "$REV" > /var/www/acornfox.new/.revision
chmod -R a+rX /var/www/acornfox.new
rm -rf /var/www/acornfox.old
[ -d /var/www/acornfox ] && mv /var/www/acornfox /var/www/acornfox.old
mv /var/www/acornfox.new /var/www/acornfox
rm -rf /var/www/acornfox.old /tmp/acornfox-site

echo "4️⃣ 配置 Caddy..."
mkdir -p /etc/caddy/sites /var/log/caddy
chown caddy:caddy /var/log/caddy
# 主 Caddyfile 只保证引入站点目录，不覆盖已有内容
if [ ! -s /etc/caddy/Caddyfile ]; then
    echo 'import /etc/caddy/sites/*.caddy' > /etc/caddy/Caddyfile
elif ! grep -qF 'import /etc/caddy/sites/*.caddy' /etc/caddy/Caddyfile; then
    cp /etc/caddy/Caddyfile "/etc/caddy/Caddyfile.bak-$(date +%Y%m%d%H%M%S)"
    printf '\nimport /etc/caddy/sites/*.caddy\n' >> /etc/caddy/Caddyfile
fi
cat > /etc/caddy/sites/acornfox-website.caddy << CADDYFILE
# AcornFox 官网（由 scripts/deploy-website.sh 生成）
${DOMAIN} {
    root * /var/www/acornfox
    file_server
    encode gzip

    header {
        X-Content-Type-Options "nosniff"
        X-Frame-Options "DENY"
        Referrer-Policy "strict-origin-when-cross-origin"
        -Server
    }

    log {
        output file /var/log/caddy/acornfox.log
        format json
    }
}

www.${DOMAIN} {
    redir https://${DOMAIN}{uri} permanent
}
CADDYFILE
if ! out=$(caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile 2>&1); then
    echo "   ❌ Caddy 配置校验失败："
    echo "$out" | tail -5
    exit 1
fi

echo "5️⃣ 启动 Caddy..."
systemctl enable --quiet caddy
if systemctl is-active --quiet caddy; then
    systemctl reload caddy
else
    systemctl start caddy
fi
sleep 2
if systemctl is-active --quiet caddy; then
    echo "   ✓ Caddy 运行正常"
else
    echo "   ❌ Caddy 启动失败"
    systemctl status caddy --no-pager | tail -20
    exit 1
fi

echo ""
echo "✅ 部署完成：/var/www/acornfox（版本 ${REV}）"
ENDSSH

echo ""
echo "🧪 验证（按服务器 IP 直连，不依赖 DNS）..."
code=$(curl -s -m 15 -o /dev/null -w "%{http_code}" --resolve "${DOMAIN}:80:${SERVER_IP}" "http://${DOMAIN}/" || true)
echo "  http://${DOMAIN} → ${code}（308 表示已跳转到 HTTPS）"
code=$(curl -s -m 15 -o /dev/null -w "%{http_code}" --resolve "${DOMAIN}:443:${SERVER_IP}" "https://${DOMAIN}/" || true)
echo "  https://${DOMAIN} → ${code}（DNS 指向本机前证书无法签发，000 属正常）"
echo ""
echo "DNS：${DOMAIN} 与 www.${DOMAIN} 需指向 ${SERVER_IP}，生效后 Caddy 会自动申请证书。"
