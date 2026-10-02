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
    echo "   安装 Caddy 依赖..."
    apt install -y debian-keyring debian-archive-keyring apt-transport-https curl

    echo "   添加 Caddy 仓库..."
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | tee /etc/apt/sources.list.d/caddy-stable.list

    echo "   安装 Caddy..."
    apt update -qq
    apt install -y caddy
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
