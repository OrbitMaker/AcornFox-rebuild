# 故障演练报告

状态：2026-08-21 现场执行完成，PASS。

| 演练 | 起始时间 | 恢复时间 | RTO | 数据校验 | 结果 |
| --- | --- | --- | --- | --- | --- |
| Demo Pod 删除 | 19:02:37Z | 19:02:41Z | 4s | N/A | PASS，3/3 恢复 |
| Higress 后端摘除 | 19:02:37Z | 19:03:02Z | 4s（后端恢复） | N/A | PASS，80 次请求零非 200 |
| PostgreSQL Primary 删除 | 19:03:37Z | 19:03:39Z | 2s（选主） | 标记一致 | PASS，`poc-postgres-1` → `-2` |
| PostgreSQL RW Service 重连 | 19:03:37Z | 演练结束 | 自动 | 12 次成功 / 2 次重试 | PASS |
| 本地 PVC Pod 重建 | 存储阶段 | 存储阶段 | <30s | marker 一致 | PASS |

原始证据保存在 `artifacts/drills/`，不把 kubeconfig、token 或密码写入本报告。

## 结论

- Demo Pod 被删除后，Deployment 在 4 秒内恢复精确 3 个 Ready Pod，旧 Pod 名称消失，Service Endpoint 恢复为 3。
- 80 次连续 Higress HTTP 请求全部返回 200，说明 Terminating Pod 被自动摘除且流量不中断。
- CNPG 在 2 秒内把 Primary 从 `poc-postgres-1` 切换到 `poc-postgres-2`。
- 同步提交标记 `failover-20260820T190337Z` 在新 Primary 可读；RW Service 客户端经历 2 次重试后自动恢复连接。
- 演练后重新运行全套 `make verify`，所有阶段再次通过。

未执行整台物理宿主断电。Open-Local 是本地卷，宿主级断电会把该节点上的卷一并带走；在引入复制存储或数据库备份前，不把 Pod 级成功扩大为物理机灾难恢复结论。

