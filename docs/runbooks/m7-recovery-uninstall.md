# M7 RC 重启、故障恢复与卸载 runbook

状态：`RUNBOOK_CONTRACT_ONLY`，当前执行状态：`NOT_RUN`。本文覆盖 `REBOOT-RECOVERY-001`、`FAULT-RC-001`、故障恢复、
`INSTALL-003` 和 `HOST-RECLAIM-001` 的安全边界。

## 1. Guest reboot / service restart

只在任务专属、已授权的验收 guest 内执行重启；共享开发机不执行宿主重启。
重启前保存四个 unit、current/previous、路由、recoverable operation/task、
outbox cursor、审计 hash 和应用卷 checksum。

```bash
sudo systemctl reboot
# guest 回来后
systemctl is-enabled open-card-server.service open-card-agent.service \
  open-card-buildkit.service open-card-caddy.service
systemctl is-active open-card-server.service open-card-agent.service \
  open-card-buildkit.service open-card-caddy.service
```

`REBOOT-RECOVERY-001` 必须证明：systemd 自启、Agent 重连、控制面恢复
recoverable operations、outbox/webhook 不重复投递、Caddy 从持久路由事实重建、
单一 serving deployment 和应用卷 checksum 不变。中断发生在任意迁移/升级阶段
时，按 `m7-upgrade.md` 的旧版本保留合同处理。

## 2. 故障处理

迁移、健康、数据库 checksum、bundle checksum 任一失败都停止候选推进并保留
旧可用版本；不要手工写成功状态。记录故障类别、阶段、lease/operation、旧
指针、候选清理结果、审计/outbox 事件和重试结果。恢复动作必须可重放、幂等、
可审计；恢复通知失败不应改变应用 serving。

## 3. 默认保留卸载

```bash
bash scripts/mvp/uninstall.sh --root "$ROOT" \
  --test-safe-prefix "$SAFE_PREFIX" --dry-run
```

默认执行移除 release/config/unit、Agent/Caddy/BuildKit 程序状态与日志、
BuildKit loop mount/image、精确 fstab 行和 scoped AppArmor profile，并保留
`/var/lib/open-card`、backups、evidence 和应用数据卷。只有用户明确选择危险模式并给出精确
`--purge --confirm OPEN-CARD-PURGE` 才可删除数据；未确认、目标 root 不匹配
或路径含 symlink 时必须拒绝。卸载后必须 `daemon-reload`，不能触碰 Docker、
其他项目卷、非任务容器或宿主全局策略。

## 4. 任务资源回收

```bash
bash scripts/mvp/clean-worker-reclaim.sh --dry-run
```

dry-run 先核对任务 marker、精确 domain/pool/disk/network、before snapshot
和资源清单。真实回收只允许已授权任务资源，按 guest 优雅关机、domain、disk、
pool、隔离 network、bundle/payload 顺序处理；最后重新枚举非任务资源、默认
路由、AppArmor、Docker/containerd、frpc 和 libvirt 状态，任何漂移都停止并
报告，不扩大删除范围。
