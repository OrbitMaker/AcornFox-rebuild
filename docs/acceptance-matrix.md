# 第一阶段验收矩阵

| 阶段 | 必须证据 | 通过条件 |
| --- | --- | --- |
| Kubernetes | nodes、conditions、system Pods、节点资源 | 4/4 Ready；Dev 可调度；无节点压力 |
| Open-Local | SC/PV/PVC、nodeAffinity、重建前后 checksum | PVC Bound；数据重启不丢；只使用数据盘 VG |
| OpenKruise | CRD/webhook、CloneSet rollout、原地升级 | CloneSet Ready；升级成功；Pod 生命周期事件可见 |
| Higress | controller/gateway、HTTP/HTTPS、Host/path | 路由 200；证书握手；后端摘除正确 |
| Demo | Deployment/EndpointSlice、连续请求、删 Pod | 3 副本；请求命中多个 Pod；自动补齐且入口持续可用 |
| PostgreSQL | Cluster/Pods/PVC、复制槽、LSN、主故障 | 3 实例/3 PVC；新 Primary 产生；测试数据 checksum 不变 |
| Monitoring | targets、PromQL、Grafana health | Node/Pod/K8s/PG/Higress 指标可查询 |
| Drills | before/after/event/RTO/checksum | 每项有明确成功判定和恢复记录 |

每阶段的自动化脚本以退出码表达结果，并在 `artifacts/<phase>/` 保存安装日志、验证日志和 Kubernetes 快照。只有验证通过才允许提交该阶段并进入下一阶段。

