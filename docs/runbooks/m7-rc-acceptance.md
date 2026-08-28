# M7 RC 验收编排合同

状态：`RUNBOOK_CONTRACT_ONLY`，当前执行状态：`NOT_RUN`，runner 仍为 `RUNNER_CONTRACT_ONLY`，不是 Gate 结果。M7 只有在 M0-M6 共享回归、
8 个 INSTALL/UPGRADE Gate、6 个 RC Gate 均有独立 active evidence、checksum
manifest 和合并 JUnit 后才能标记 PASS；fixture 与 runbook 本身不能晋级
里程碑。

## 冻结矩阵

| 类别 | Test IDs | 主要事实 |
| --- | --- | --- |
| 安装 | `INSTALL-001` `INSTALL-002` `INSTALL-003` | 干净安装、离线校验、保留式卸载 |
| 升级 | `UPGRADE-001`…`UPGRADE-005` | N-1/N、迁移失败、Agent 兼容、Caddy 重建、DB 恢复 |
| RC | `RC-SUPPLY-001` | bundle、资产、SBOM、依赖和 checksum |
| RC | `BACKUP-RESTORE-001` | 控制面/卷/审计恢复 |
| RC | `REBOOT-RECOVERY-001` | guest reboot、自启、任务恢复 |
| RC | `FAULT-RC-001` | 服务/事件中断、有限重试、单副作用收敛 |
| RC | `SECURITY-RC-001` | 路径、manifest、权限、网络和资源越权负向 |
| RC | `E2E-RC-001` | 离线安装→重启→升级→失败恢复→备份恢复→卸载 |
| RC | `REGRESSION-RC-001` | M0-M6 共享契约回归与范围冻结 |
| RC | `HOST-RECLAIM-001` | 精确任务资源回收与宿主 before/after 无漂移 |

## 执行顺序

1. 在干净 Ubuntu 24.04 amd64 guest 采集 host/guest before snapshot，验证
   任务资源 marker、无 host mount/device、无外网转发和无生产 DNS/证书。
2. 执行 `RC-SUPPLY-001`：canonical bundle、Ubuntu image、离线 deb/资产和
   每个文件 SHA-256 必须来自固定 manifest；篡改/缺失立即停止。
3. 按 `m7-install.md` 执行 INSTALL 三项，再执行 reboot/recovery。
4. 按 `m7-upgrade.md` 执行 UPGRADE 五项；迁移失败、健康失败、兼容越界和
   Caddy runtime 丢失均必须验证旧事实继续可用。
5. 执行 `BACKUP-RESTORE-001`、`SECURITY-RC-001` 和全链
   `E2E-RC-001`。所有中间阶段都输出独立 result/objects/events/manifest，
   `NOT_RUN` 不能写成 `PASS`。
6. 最后运行 `HOST-RECLAIM-001`，精确删除任务 domain/qcow2/pool/network/
   bundle/payload/temp，并证明非任务资源和宿主核心状态与 before 相同。

## 证据与停止条件

每个 Test ID 至少应有 terminal log、systemd 状态、版本/迁移快照、对象或
数据库查询、关键 checksum、故障前后状态和 JUnit。HTTP 200、容器存在、单个
健康响应或代码存在都不是独立 Gate 证据。任一高危越权、明文密钥、不可恢复
迁移、重复副作用、宿主漂移或 evidence 缺失都使 M7 保持 `IN_PROGRESS /
NOT PASSED`，并将失败包隔离到 negative/superseded，不得污染 active evidence。
