# N5 安装脚本测试计划

## 测试环境

### 国内环境
- 阿里云 Ubuntu 22.04（推荐）
- 腾讯云 Ubuntu 22.04
- 华为云 Ubuntu 22.04

### 海外环境
- AWS Ubuntu 22.04
- DigitalOcean Ubuntu 22.04
- Linode Ubuntu 22.04

## 测试脚本

### 1. 基础安装测试

```bash
# 在干净的 Ubuntu 22.04 服务器上执行
curl -fsSL https://raw.githubusercontent.com/acornfox/acornfox/main/scripts/install/install.sh | sudo bash
```

### 2. 中国镜像源测试

```bash
# 强制使用中国镜像
curl -fsSL https://raw.githubusercontent.com/acornfox/acornfox/main/scripts/install/install.sh | sudo bash -s -- --china
```

### 3. 跳过已安装组件测试

```bash
# 已有 Docker，跳过 Docker 安装
curl -fsSL https://raw.githubusercontent.com/acornfox/acornfox/main/scripts/install/install.sh | sudo bash -s -- --skip-docker

# 已有 Caddy，跳过 Caddy 安装
curl -fsSL https://raw.githubusercontent.com/acornfox/acornfox/main/scripts/install/install.sh | sudo bash -s -- --skip-caddy
```

## 验收清单

### 安装验收

- [ ] 服务器可以通过 SSH 访问
- [ ] Docker 已安装并运行（`docker ps` 成功）
- [ ] Caddy 已安装（`caddy version` 成功）
- [ ] 系统账号已创建
  - [ ] `acornfox` 用户存在
  - [ ] `acornfox-exec` 用户存在
  - [ ] `acornfox-ipc` 组存在
  - [ ] `acornfox-users` 组存在
- [ ] 数据目录已创建
  - [ ] `/var/lib/acornfox/` 存在且权限 750
  - [ ] `/run/acornfox/` 存在且权限 2770
- [ ] 数据库已初始化
  - [ ] `/var/lib/acornfox/data/acornfox.db` 存在且权限 600
  - [ ] 数据库包含所有必需的表
- [ ] systemd 服务已配置
  - [ ] `/etc/systemd/system/acornfox-server.service` 存在
  - [ ] `/etc/systemd/system/acornfox-runner.service` 存在
- [ ] 服务已启动并运行
  - [ ] `systemctl status acornfox-server` 显示 active (running)
  - [ ] `systemctl status acornfox-runner` 显示 active (running)
- [ ] 管理员令牌已生成
  - [ ] `/root/.acornfox-token` 存在且权限 600
  - [ ] 令牌是 64 位十六进制字符串

### CLI 连接测试

在本地电脑上：

```bash
# 1. 安装 CLI
curl -fsSL https://acornfox.dev/install-cli.sh | bash

# 2. 配置目标服务器
acornfox target add test-server --ssh user@<server-ip>

# 3. 测试连接
acornfox apps

# 4. 打开控制台
acornfox open
```

验收：
- [ ] CLI 可以通过 SSH 连接到服务器
- [ ] `acornfox apps` 返回空列表（无错误）
- [ ] `acornfox open` 成功打开浏览器控制台
- [ ] 控制台显示登录页面

### 应用部署测试

```bash
# 部署测试应用
mkdir test-app && cd test-app
echo 'FROM nginx:alpine' > Dockerfile
acornfox deploy
```

验收：
- [ ] 部署成功并返回访问 URL
- [ ] 浏览器可以访问应用
- [ ] 应用显示 nginx 欢迎页面

### 镜像加速测试（仅国内）

```bash
# 查看 Docker 配置
cat /etc/docker/daemon.json

# 测试拉取镜像速度
time docker pull nginx:alpine
```

验收：
- [ ] `daemon.json` 包含国内镜像源配置
- [ ] 拉取镜像速度正常（< 30 秒）

## 故障诊断

### 服务启动失败

```bash
# 查看服务日志
journalctl -u acornfox-server -n 50
journalctl -u acornfox-runner -n 50

# 检查端口占用
ss -tlnp | grep 18800

# 检查 Docker 连接
docker ps
```

### 数据库问题

```bash
# 检查数据库文件
ls -la /var/lib/acornfox/data/

# 查看数据库内容
sqlite3 /var/lib/acornfox/data/acornfox.db ".tables"
```

### 权限问题

```bash
# 检查用户和组
id acornfox
id acornfox-exec
getent group acornfox-ipc
getent group acornfox-users

# 检查目录权限
ls -ld /var/lib/acornfox
ls -ld /run/acornfox
```

## 已知问题

1. **首次安装时 Docker 镜像拉取慢**
   - 解决方案：使用 `--china` 参数配置镜像加速

2. **Caddy 在国内下载慢**
   - 解决方案：脚本已使用 ghproxy 加速

3. **Ubuntu 20.04 上 systemd 服务偶发启动慢**
   - 解决方案：增加 `RestartSec=5s` 延迟

## 清理测试环境

```bash
# 停止服务
sudo systemctl stop acornfox-server acornfox-runner

# 删除服务文件
sudo rm /etc/systemd/system/acornfox-*.service
sudo systemctl daemon-reload

# 删除数据
sudo rm -rf /var/lib/acornfox /run/acornfox

# 删除二进制
sudo rm /usr/local/bin/acornfox

# 删除用户和组
sudo userdel -r acornfox
sudo userdel -r acornfox-exec
sudo groupdel acornfox-ipc
sudo groupdel acornfox-users

# 可选：删除 Docker 和 Caddy
# sudo apt-get remove --purge docker-ce docker-ce-cli containerd.io caddy
```

## 下一步

完成安装脚本测试后，进入 N5.3 升级脚本测试。
