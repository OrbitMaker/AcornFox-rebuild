# M7 RC 备份与恢复 runbook

状态：`RUNBOOK_CONTRACT_ONLY`，当前执行状态：`NOT_RUN`。本文冻结 `BACKUP-RESTORE-001`，也作为
`UPGRADE-001`/`UPGRADE-005` 的共同恢复合同。

## 1. 生成一致性备份

```bash
bash scripts/mvp/backup-control-plane.sh --root "$ROOT" \
  --reason pre-upgrade-0.5.0-rc1 --release-version 0.5.0-rc1 \
  --test-safe-prefix "$SAFE_PREFIX" --dry-run
```

如果 `OPEN_CARD_DATABASE_URL` 或 `DATABASE_URL` 存在，正式备份必须同时提供
绝对路径、可执行的 pg_dump-compatible command：

```bash
bash scripts/mvp/backup-control-plane.sh --root / \
  --reason pre-upgrade-0.5.0-rc1 --release-version 0.5.0-rc1 \
  --database-dump-command /usr/local/libexec/open-card-pg-dump
```

脚本必须拒绝相对 root、HOME 下路径、symlink data path、未提供数据库 dump
command 的 configured database URL，以及不安全 reason。metadata 至少包含
`backup_id`、UTC `created_at`、archive 名称、archive SHA-256、consistency、
reason 和 release version；`backups` 不能被再次归档。

## 2. 校验与恢复

```bash
bash scripts/mvp/restore-control-plane.sh --root "$ROOT" \
  --backup "$BACKUP_METADATA_OR_ARCHIVE" \
  --database-restore-command "$PG_RESTORE_COMMAND" \
  --test-safe-prefix "$SAFE_PREFIX" --dry-run
```

正式恢复顺序：停止/隔离受影响的控制面写入，验证 metadata/archive/dump
checksum，验证 tar 成员是相对普通文件，解压到同父目录的临时 stage，再原子
替换 data/config directory，并通过显式 restore command 导入已校验 SQL dump。
任一步失败必须恢复旧目录或进入明确的 recovery-required 停止状态，不能把
只恢复文件系统冒充 PostgreSQL 恢复。

## 3. 恢复验收

恢复后按顺序核对 schema migration checksum、audit hash chain、Release 与
Deployment 关系、route-set/current pointer、应用卷 checksum、recoverable
task/outbox、日志/用量摘要和四个 systemd unit。只有所有事实一致并通过健康
与本地流量检查，才可以恢复 serving；否则保持旧路由/停止写入并标记失败。
恢复不回滚应用数据卷，也不删除审计/evidence。
