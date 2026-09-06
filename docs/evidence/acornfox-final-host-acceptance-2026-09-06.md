# AcornFox v0.1.0-beta.1 发布验收

首个单机公开开源 Beta 已完成实机验收并发布：
https://github.com/EleJiuDeiChi/acornfox/releases/tag/v0.1.0-beta.1

GitHub 读回 `draft=false`、`prerelease=true`、`immutable=true`。公开 main 和版本标签指向同一份已验收源码；六个发布附件经过匿名下载及完整 SHA-256 核对。原 `EleJiuDeiChi/open-card` 私有仓库及历史未公开。

## 精确版本

- 源码：`6ed40027c0ac892e404c31e5daafaf0749eec216`
- 安装版本：`0.1.0-beta.1`
- Candidate binding：`9e796c8a527bf559e7636219eacb98933410f768630867eddc38876492963095`
- 安装包 SHA-256：`ef4722471203272dc0961c63a1d32a275b6ec44a82cf600f992c16fb7aaf849d`
- 内部升级测试包：同一源码构建的 `0.1.0-beta.2`，binding `6d4cff7db9b935cf8e479f24efb4acb92c37cbbc4b670e6c37ffcaac9c459e41`，精确绑定上述前驱；未对外发布。

两包在阿里云专用 Ubuntu 24.04 amd64 主机离线构建，分别耗时 92.32 秒、90.83 秒，并通过 installer-owned verification。最终演示环境重新安装了同一个公开 Beta 1 包。

## 实际通过的流程

| 验收 | 结果 |
|---|---|
| 正式安装入口 | 安装包正常完成安装，返回 `installed/ok=true`；未手改产品二进制、权限或配置绕过检查 |
| 真实公开 Git | 同一阿里云主机临时只读 HTTPS Git 提供已审查的 f78b7df 示例；产品 DNS、IP 固定、TLS 和源码限制不变 |
| 构建与运行 | 新候选导入 0.69 秒、构建 0.86 秒；Dockerfile 实际执行 RUN，无 COPY chmod 绕过；容器运行并响应 HTTP 200 |
| 用户响应检查 | 安装版 CLI 的 probe 与真实浏览器“检查应用响应”按钮均通过；收到新的 Agent responded / HTTP 200 记录 |
| 公网访问 | 可信 HTTPS、正确应用内容与原 Host；关闭后 404，再启用成功 |
| 日常操作 | 构建/运行日志接口可读；重启成功；重新部署更换容器后保留原端口，原公网 URL 继续 200 |
| 网关重启 | Edge 单独重启后从数据库恢复路由，服务器外再次访问 200 |
| 中断升级 | 真实升级在持久 SWITCHED 阶段 SIGKILL，应用仍运行；随后真实重启服务器，ROLLED_BACK、原容器自动运行、内部及公网 HTTP 200 |
| 正常升级 | 对同一精确前驱/后继重试，UPGRADED，应用容器 ID 不变且未额外重启；核心数据行摘要及五份运行证书/密钥摘要不变 |
| 发布分发 | 精确六件套上传核对、版本与附件锁定、匿名下载完整字节摘要一致 |
| 会话收尾 | 浏览器上下文关闭；会话 helper 清理结果 0；临时 Git 服务归档、独立 DNS 记录删除，产品配置恢复 |

正常升级后的首次即时公网检查遇到网关路由尚未重建的短暂 HTTP 错误。升级进程已成功退出且 journal 已为 UPGRADED；随后只读等待并确认路由收敛，没有再次执行升级。单机升级不承诺零中断。

## 本轮主要修改与简化

- `web/src/acornfox/App.tsx`、`client.ts`、`types.ts`：补齐用户可操作的响应检查，复用既有请求作用域和权威状态回读。
- `cmd/acornfox/commands.go`、`client.go`：CLI 提供固定 HTTP 根路径 probe，保留严格路径、202、CSRF 和幂等限制。
- `internal/persistence/postgres/acornfox_public_access.go`：所属资源缺少或过期响应证据返回明确 409，外来资源仍 404。
- `internal/providers/standalone/restore.go`、`state.go` 和 Agent 网络接入：网络保护完成后恢复原 active 容器；核对实际网络附件、原 ID、资源和端口，不启用无保护的 Docker 自动重启。
- `internal/providers/standalone/replacement.go`、`provider.go`、`state.go`：同一部署替换保留原资源租约和端口，消除每次重部署重新配置公网入口的手工步骤；中断重放和取消释放有明确持久状态。
- `docs/acornfox/install.md`：安装流程补齐 running → 检查响应 → 公网启用。

变更分别通过独立 GPT-6 审查。整合后前端 lint/typecheck、179 项测试、18 项 CLI/Web API parity 通过；最终冻结源码在阿里云通过 standalone、Agent、CLI、Server 测试及 vet。状态机变更另有 race、故障注入和 Linux 编译验证。

## 证据索引

结构化证据位于 `.omx/evidence/aliyun-mvp-20260905/`；截图另存于仓库 `.codex-artifacts/`。这些记录不公开凭据：

- `beta1-final-candidate/`：已安装、发布的精确六件套。
- `final-upgrade-proof/`：before、SWITCHED 中断、真实重启 rollback、正常 retry 的绑定与事实摘要。
- `final-demo-readback.json`：最终演示安装的版本、binding、服务和公网访问读回。
- `final-browser-acceptance.json`：实际浏览器登录、响应检查、源码链接与应用页面结果。
- `release-upload-verification.json`：六件套上传核对。
- `public-release-download-verification.json`：公开 main/tag、immutable 状态和六件套匿名下载核对。大附件从同一匿名发布 URL 使用已核对的 HTTP 206 范围续传，拼接后核对完整摘要。
- `.codex-artifacts/browser-media/final-beta1-*.png`：实际浏览器页面。

早期 e54f981e / cc750 候选发现的端口漂移和重启不恢复是已记录的失败，不用于替代本次验收；对应旧证据保留在 `old-beta1-e54-upgrade/`。更早的纯模拟和不带运行容器的升级记录也不计入本次通过结论。`build-record.json` 保留构建阶段的事实，不自行宣称完成主机验收。

## 首版边界

专用 Ubuntu 24.04 amd64、单机、公开 Git、根目录 Dockerfile、单应用单容器。RUN 不提供一般互联网访问。私有 Git、Compose、多服务、应用数据库/数据卷、AI 修复和 Kubernetes 未列入此次发布；未宣称客户业务验收或多机高可用。

测试实例计划于 2026-09-07 16:21（北京时间）自动释放。管理台和示例应用保留用于本轮查看，临时 Git 测试入口已关闭。

## 后续资源变更

2026-09-06 用户要求释放原测试机并改用最低价2核4G/50G机器。原实例及系统盘现已释放，原演示地址不再使用；新机器安装与实际运行验证见 [低配安装测试](acornfox-2c4g-install-2026-09-06.md)。上述首版发布与验收证据不因测试机释放而改变。
