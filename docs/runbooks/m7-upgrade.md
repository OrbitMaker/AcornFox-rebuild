# M7 RC 升级、失败回退与兼容 runbook

状态：`RUNBOOK_CONTRACT_ONLY`，当前执行状态：`NOT_RUN`。本文覆盖 `UPGRADE-001` 至 `UPGRADE-005`，不
把一次 dry-run、版本字符串或 HTTP 响应当作升级通过。

## 1. 升级前快照

升级必须先记录当前 release pointer、data schema version、Agent protocol、
服务状态、路由事实、应用卷 checksum 和审计 hash。执行
`backup-control-plane.sh` 生成控制面一致性快照；若配置数据库 URL，必须给
出显式可执行的 pg_dump-compatible command，不能静默退化为 filesystem-only
归档。

```bash
bash scripts/mvp/upgrade.sh --root "$ROOT" --bundle "$CANDIDATE_BUNDLE" \
  --offline --test-safe-prefix "$SAFE_PREFIX" --dry-run
```

## 2. `UPGRADE-001` N-1 → N

候选 bundle 的 manifest 必须声明当前 data version 和 Agent protocol 在兼容
窗口内，且版本 major 不变。升级器先备份，再校验候选文件集合/checksum/mode，
执行事务迁移，最后原子切换 `current`。健康命令成功后才允许让候选服务继续
承接流量；应用卷和审计事实不因代码升级被替换。

```bash
bash scripts/mvp/upgrade.sh --root / --bundle "$CANDIDATE_BUNDLE" \
  --offline --expected-manifest-sha256 "$PUBLISHED_MANIFEST_SHA256" \
  --migration-command "$MIGRATE_COMMAND" --migration-dir "$MIGRATIONS_CURRENT" \
  --database-dump-command "$PG_DUMP_COMMAND" \
  --database-restore-command "$PG_RESTORE_COMMAND" \
  --health-command /usr/local/libexec/open-card-health --activate
```

证据至少包括：旧/新版本与 release identity、migration rows/checksum、
current/previous 指针、四个 unit 状态、持续请求、卷 checksum、审计/outbox
事件和恢复后的健康事实。

## 3. `UPGRADE-002` 迁移失败

在受控测试事务中注入一次失败。期望是迁移事务整体回滚，旧 release、旧 data
version、旧路由和运行应用继续可用；候选目录可以保留为可审计失败对象，但
不得成为 current，也不得产生半成功 Operation。重启控制面后再次读取事实，
不能手工把数据库改成成功。

## 4. `UPGRADE-003` Agent/API 兼容

逐项运行固定矩阵：server 1.1 + Agent 1.0、server 1.1 + Agent 1.1 必须在
兼容窗口内工作；不兼容 major 必须显式拒绝。未知安全字段、缺失必选字段和
能力越权不能静默降级。记录协商版本、capabilities、拒绝错误和 mTLS 身份。

## 5. `UPGRADE-004` Caddy 重建

删除的是派生 runtime config，不是 Open Card 路由事实。重启 Caddy 后必须从
持久 route-set 重建，验证 loopback admin、配置 hash、路由冲突拒绝、IP
fallback 和持续流量。若重建失败，保留上一可用路由和应用，不重新构建镜像。

## 6. `UPGRADE-005` 数据库恢复

数据库损坏/不可用故障只能通过已校验 backup metadata/archive 恢复。恢复脚本
先校验 archive 与 database dump checksum，stage 后再替换数据目录；dump
由显式 `--database-restore-command` 导入，不可被 filesystem restore 冒充。
缺失命令或导入失败必须停止
控制面并写 `recovery-required.json`，不可只回退二进制指针。恢复后
核对 audit hash chain、release/deployment 关系、route facts、卷 checksum、
outbox/recoverable operations 和四个 unit，再决定是否恢复流量。
