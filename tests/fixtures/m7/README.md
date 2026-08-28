# Open Card M7 RC fixtures

这是 M7 安装、升级、恢复、兼容、安全硬化和回收验收的确定性数据-only
fixture。它冻结支持矩阵、目录/服务契约、离线 bundle manifest、备份恢复
校验、故障分类和任务资源回收边界；它不创建 VM，不激活宿主 systemd，
也不代表任何真实 RC Gate 已通过。

首个正式支持目标严格收敛为 Ubuntu 24.04 LTS amd64。Docker Engine 是外部
preflight 依赖；控制面四个 systemd unit 的名称、安装目录和数据目录必须与
fixture 一致。在线安装仅在明确允许网络的验收环境使用；离线安装必须只消费
manifest 已校验的 bundle，不能从 ambient APT 或未固定 URL 补包。

冻结 Gate：

- `INSTALL-001`、`INSTALL-002`、`INSTALL-003`；
- `UPGRADE-001`、`UPGRADE-002`、`UPGRADE-003`、`UPGRADE-004`、`UPGRADE-005`；
- `RC-SUPPLY-001`、`BACKUP-RESTORE-001`、`REBOOT-RECOVERY-001`、
  `SECURITY-RC-001`、`E2E-RC-001`、`HOST-RECLAIM-001`。
  `FAULT-RC-001` 和 `REGRESSION-RC-001` 也必须分别留存故障恢复与
  M0-M6 共享契约回归证据。

每个真实 Gate 必须另行写入独立 evidence、终端日志、对象/文件快照、
checksum 和 JUnit。这里的 `NOT_RUN`/`RUNNER_CONTRACT_ONLY` 只能表达合同，
不能被汇总器当作 PASS。
