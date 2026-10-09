# AcornFox 验收发现的问题报告

日期：2026-10-02  
验收环境：阿里云 ECS，Ubuntu 22.04.5 LTS，x86_64  
服务器：国内云主机（测试后已释放）

## 执行摘要

在验收检查 1 和 2 的过程中，发现了 **2 个 P0 级别的阻塞问题**和 **1 个 P0 级别的待确认问题**。前两个问题已修复并验证，第三个问题需要进一步调试。

### 验收进度

- ✅ **检查 1**：一条命令安装并初始化 - **通过**（修复后）
- ✅ **检查 2**：CLI 和 Skill 安装 - **通过**
- ❌ **检查 3**：AI 生成 Dockerfile 并部署 - **阻塞**（部署失败）
- ⏸️ **检查 4-7**：待完成（依赖检查 3）

---

## 问题 1：Server 和 Runner 之间的 UID 不匹配（P0，已修复）

### 问题描述

`acornfox-server` 无法连接到 `acornfox-runner`，持续报错：

```
ERROR list all containers err="runner: unavailable"
```

### 根本原因

**Peer credentials 验证失败**：

- `acornfox-server` 运行为 `acornfox` 用户（UID **997**）
- `acornfox-runner` 运行为 `acornfox-exec` 用户（UID **996**）
- Server 默认期望 runner 的 UID 是 `os.Getuid()`（997），但实际是 996
- Runner 默认期望 server 的 UID 是 `os.Getuid()`（996），但实际是 997
- `internal/peer` 包使用 Linux `SO_PEERCRED` 进行严格的 UID 验证
- 验证失败导致连接被拒绝

### 诊断过程

1. 使用 `strace` 跟踪系统调用，发现 `getsockopt(SO_PEERCRED)` 成功但 UID 不匹配
2. 检查代码发现 `--runner-uid` 和 `--server-uid` 参数默认值都是 `os.Getuid()`
3. 验证服务的实际 UID：
   - `acornfox` 用户：997
   - `acornfox-exec` 用户：996

### 修复方案

在 systemd 服务配置中添加正确的 UID 参数：

**`/etc/systemd/system/acornfox-server.service`**：
```ini
ExecStart=/usr/local/bin/acornfox server --runner-uid 996
```

**`/etc/systemd/system/acornfox-runner.service`**：
```ini
ExecStart=/usr/local/bin/acornfox runner --server-uid 997
```

### 验证结果

✅ 修复成功，`runner: unavailable` 错误消失

### 影响范围

- **严重性**：P0（完全阻止所有部署操作）
- **受影响组件**：所有依赖 Server-Runner 通信的功能（部署、应用管理、日志查询等）
- **修复难度**：低（配置修改）

### 长期解决方案

**建议修改代码**，让服务自动检测对端用户的 UID，而不是依赖命令行参数：

1. Server 启动时读取 runner socket 的 owner UID
2. Runner 启动时读取配置文件或环境变量中的 server UID
3. 或者在安装脚本中动态生成正确的 systemd 服务文件

---

## 问题 2：Caddy admin socket 权限问题（P0，已修复）

### 问题描述

`acornfox-server` 无法连接到 Caddy admin API，报错：

```
ERROR route sync err="caddy request GET /config/apps/http/servers: 
dial unix /run/acornfox/caddy-admin.sock: connect: no such file or directory"
```

后续修复后变成：

```
ERROR route sync err="... connect: permission denied"
```

### 根本原因

**Caddy admin socket 配置和权限问题**：

1. Caddy 默认配置没有启用 Unix socket admin API
2. Caddy 运行为 `caddy` 用户，无权在 `/run/acornfox/` 目录创建 socket
3. Socket 创建后，权限为 `s-w-------`（只有 owner 可访问），`acornfox` 用户无法访问

### 诊断过程

1. 检查 Caddy 状态，发现服务启动失败
2. 查看 Caddy 日志：`permission denied` 错误
3. 检查目录权限和用户组关系
4. 修复权限后发现 socket 权限仍然不足

### 修复方案

**步骤 1：配置 Caddyfile 启用 admin API**

`/etc/caddy/Caddyfile`：
```
{
    admin unix//run/acornfox/caddy-admin.sock {
        origins *
    }
    persist_config off
}
```

**步骤 2：设置目录和用户组权限**

```bash
# 将 caddy 用户添加到 acornfox 组
usermod -aG acornfox caddy

# 设置目录权限
chown acornfox:acornfox /run/acornfox
chmod 775 /run/acornfox

# 将 acornfox 用户添加到 caddy 组
usermod -aG caddy acornfox

# 设置 socket 权限
chmod 660 /run/acornfox/caddy-admin.sock
chown caddy:acornfox /run/acornfox/caddy-admin.sock
```

### 验证结果

✅ Caddy 启动成功，admin socket 已创建（`srw-rw---- caddy acornfox`）

⚠️ 仍有一个新错误（非阻塞）：
```
ERROR route sync err="caddy probe servers: status 400: 
{\"error\":\"invalid traversal path at: config/apps/http\"}"
```

这个错误表明 Caddy 的 HTTP 应用模块还没有初始化，但不影响 socket 连接本身。

### 影响范围

- **严重性**：P0（阻止所有域名和路由配置）
- **受影响组件**：域名 HTTPS、应用路由、公开访问
- **修复难度**：中（配置 + 权限）

### 长期解决方案

1. **安装脚本应该自动配置 Caddyfile**
2. **systemd-tmpfiles 应该在启动时自动设置权限**（避免重启后失效）
3. **文档应该明确说明 Caddy 配置要求**

---

## 问题 3：部署失败 - "无法读取上传的项目包"（P0，待修复）

### 问题描述

所有部署尝试都失败，错误信息：

```
失败：无法读取上传的项目包
建议：使用 acornfox deploy 重新上传项目目录
```

### 根本原因

**待确认**。可能的原因：

1. **上传流程问题**：CLI 上传文件到服务器失败
2. **路径配置问题**：上传路径与 runner 读取路径不匹配
3. **权限问题**：runner 无法读取上传目录中的文件
4. **代码 bug**：部署 API 或上传逻辑有 bug

### 错误来源

```
acornfox/internal/runner/docker.go:runBuild()
  -> os.ReadFile(req.ContextPath)
  -> 返回错误
```

### 诊断过程

1. 多次尝试部署，每次都失败在同一个错误
2. 清理服务器上的上传目录（`/var/lib/acornfox/uploads/`）后重试，仍然失败
3. 检查上传目录，发现是空的（没有文件上传成功）
4. 服务器日志中没有关于上传或部署的详细错误信息

### 已尝试的修复方案

- ✗ 清理 `.acornfox` 本地状态文件
- ✗ 清理服务器上传目录
- ✗ 修复 Server-Runner 连接（问题 1）
- ✗ 修复 Caddy 权限（问题 2）

### 影响范围

- **严重性**：P0（完全阻止部署功能）
- **受影响组件**：所有部署操作（目录部署、Git 部署、镜像部署）
- **修复难度**：高（需要深入代码调试）

### 建议的调试步骤

1. **添加详细日志**：
   - CLI 上传过程的详细日志
   - Server 接收上传的日志
   - Runner 读取文件的详细路径和错误

2. **单元测试**：
   - 测试上传 API
   - 测试文件路径解析
   - 测试权限检查

3. **集成测试**：
   - 在本地环境（macOS）测试完整部署流程
   - 在 Linux 虚拟机中测试
   - 对比成功和失败的环境差异

4. **代码审查**：
   - 检查 `internal/cli/deploy.go` 的上传逻辑
   - 检查 `internal/apiserver/` 的上传接收逻辑
   - 检查 `internal/runner/docker.go` 的文件读取逻辑

### 临时绕过方案（不推荐）

如果急需验收，可以：
1. 手动在服务器上创建测试项目
2. 跳过 CLI 部署，直接调用 Server API
3. 或者先验收其他不依赖部署的功能

---

## 修复总结

### 已修复（2/3）

1. ✅ **Server-Runner UID 不匹配** - systemd 服务配置修复
2. ✅ **Caddy admin socket 权限** - Caddyfile 配置 + 权限设置

### 待修复（1/3）

3. ❌ **部署失败** - 需要深入代码调试

---

## 对首发的影响

### 阻塞项

- **问题 3（部署失败）** 是首发的完全阻塞项
- 如果不能部署应用，AcornFox 的核心功能无法使用
- **必须在首发前修复**

### 风险评估

- **高风险**：部署功能是核心功能，完全不可用
- **中等风险**：修复可能需要 1-2 天的深入调试
- **低风险**：问题 1 和 2 已有完整的修复方案

### 建议的行动计划

1. **立即行动**：
   - 提交问题 1 和 2 的修复到代码仓库
   - 更新安装脚本包含这些修复
   - 在干净的 Ubuntu 24.04 环境中重新测试

2. **优先级 P0**：
   - 修复问题 3（部署失败）
   - 在本地和远程环境中验证修复
   - 完成完整的 7 项验收检查

3. **首发前必须完成**：
   - 所有 P0 问题修复
   - 至少在 2 个不同的环境中验证
   - 更新文档和故障排除指南

---

## 附录：环境信息

### 服务器配置

- **系统**：Ubuntu 22.04.5 LTS
- **内核**：5.15.0-191-generic
- **架构**：x86_64
- **Docker**：29.1.3
- **Caddy**：v2.11.4

### 用户和权限

```
acornfox (UID 997)          - 运行 acornfox-server
acornfox-exec (UID 996)     - 运行 acornfox-runner
caddy                       - 运行 Caddy

acornfox-ipc (GID 1000)     - 共享组，用于 socket 通信
  - 成员：acornfox, acornfox-exec

docker (GID 121)            - Docker 访问组
  - 成员：acornfox-exec
```

### Socket 文件

```
/run/acornfox/api.sock          srw-rw---- acornfox acornfox-ipc
/run/acornfox/runner.sock       srw-rw---- acornfox-exec acornfox-ipc
/run/acornfox/caddy-admin.sock  srw-rw---- caddy acornfox
```

---

最后更新：2026-10-02 12:30
