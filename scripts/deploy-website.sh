#!/bin/bash
set -e

# AcornFox 官网部署脚本
# 用途：自动部署官网到阿里云服务器

SERVER_IP="${SERVER_IP:-<server-ip>}"
SERVER_USER="${SERVER_USER:-root}"
DOMAIN="${DOMAIN:-acornfox.com}"

echo "🚀 开始部署 AcornFox 官网"
echo "目标服务器: ${SERVER_USER}@${SERVER_IP}"
echo "域名: ${DOMAIN}"
echo ""

# 检查 SSH 连接
echo "📡 测试 SSH 连接..."
if ! ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=no "${SERVER_USER}@${SERVER_IP}" 'echo "✓ SSH 连接成功"'; then
    echo "❌ SSH 连接失败"
    echo "请确保："
    echo "  1. 服务器 IP 正确"
    echo "  2. SSH 密钥已配置或可以输入密码"
    echo "  3. 安全组已开放 22 端口"
    exit 1
fi

# 在服务器上执行部署
echo ""
echo "📦 开始远程部署..."
ssh -o StrictHostKeyChecking=no "${SERVER_USER}@${SERVER_IP}" << 'ENDSSH'
set -e

echo "1️⃣ 更新系统包..."
apt update -qq

echo "2️⃣ 检查并安装 Git..."
if ! command -v git &> /dev/null; then
    apt install -y git
fi

echo "3️⃣ 检查并安装 Caddy..."
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

echo "4️⃣ 克隆 GitHub 仓库..."
cd /var/www
if [ -d "AcornFox-rebuild" ]; then
    echo "   仓库已存在，更新代码..."
    cd AcornFox-rebuild
    git fetch origin
    git reset --hard origin/main
    cd ..
else
    echo "   首次克隆仓库..."
    git clone https://github.com/OrbitMaker/AcornFox-rebuild.git
fi

echo "5️⃣ 部署官网文件..."
mkdir -p /var/www/acornfox
cp -r AcornFox-rebuild/website/* /var/www/acornfox/
chmod -R 755 /var/www/acornfox

echo "6️⃣ 配置 Caddy..."
cat > /etc/caddy/Caddyfile << 'CADDYFILE'
# AcornFox 官网配置
acornfox.com, www.acornfox.com {
    root * /var/www/acornfox
    file_server
    encode gzip

    # 安全头
    header {
        X-Content-Type-Options "nosniff"
        X-Frame-Options "DENY"
        X-XSS-Protection "1; mode=block"
        Referrer-Policy "no-referrer-when-downgrade"
    }

    # 日志
    log {
        output file /var/log/caddy/acornfox.log
        format json
    }
}

# 默认响应（IP 直接访问）
:80 {
    respond "AcornFox - Server Running" 200
}
CADDYFILE

echo "7️⃣ 启动 Caddy 服务..."
systemctl enable caddy
systemctl restart caddy

echo "8️⃣ 检查服务状态..."
if systemctl is-active --quiet caddy; then
    echo "   ✓ Caddy 运行正常"
else
    echo "   ❌ Caddy 启动失败"
    systemctl status caddy
    exit 1
fi

echo ""
echo "✅ 部署完成！"
echo ""
echo "📊 服务信息："
echo "  - 文档根目录: /var/www/acornfox"
echo "  - Caddy 配置: /etc/caddy/Caddyfile"
echo "  - 日志目录: /var/log/caddy/"
echo ""
echo "🌐 访问测试："
echo "  - IP 访问: http://<server-ip>"
echo "  - 域名访问: http://acornfox.com (需配置 DNS)"
echo ""
ENDSSH

# 本地验证
echo ""
echo "🧪 验证部署..."
if curl -sS -o /dev/null -w "%{http_code}" "http://${SERVER_IP}" | grep -q "200"; then
    echo "✓ HTTP 访问正常"
else
    echo "⚠️  HTTP 访问异常，请检查防火墙规则"
fi

echo ""
echo "🎉 部署成功完成！"
echo ""
echo "📋 下一步操作："
echo "  1. 配置 DNS 解析（acornfox.com → ${SERVER_IP}）"
echo "  2. 等待 DNS 生效后访问 https://acornfox.com"
echo "  3. Caddy 会自动申请 HTTPS 证书"
echo ""
