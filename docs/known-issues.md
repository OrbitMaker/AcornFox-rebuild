# 已知问题

1. 单控制面不是高可用控制平面；开发机故障时 Kubernetes API 不可用。
2. Open-Local `v0.7.1` 发布较早，公开兼容矩阵未覆盖 Kubernetes 1.34；本仓库把安装与存储冒烟作为硬门禁。若门禁失败，下一候选是 OpenEBS Local PV LVM，不静默切换。
3. OpenKruise `v1.9.1` 的官方矩阵未声明 Kubernetes 1.34；必须以 webhook、CloneSet 创建和原地升级实测为准。
4. Open-Local 是节点本地存储，不提供节点间数据副本。节点宕机不等同于 Pod 重启，不能用它证明跨节点数据可用。
5. 四个 VM 使用 macvtap 直连 LAN。宿主与同宿主 guest 之间可能受 macvtap 隔离影响，管理验收应从局域网管理机执行。
6. Higress 为节省资源使用单网关副本；可验证后端 Pod 故障切换，但不能证明网关自身高可用。
7. 4GiB 节点运行完整监控、网关和三实例 PostgreSQL 的余量有限；阶段门禁会检查 OOMKilled 和节点压力。
8. `192.168.31.71-74` 已在 VM 内静态配置，但尚未验证路由器侧 DHCP 保留；必须补做 MAC/IP 绑定以避免未来地址冲突。
9. 冷安装通过国内镜像缓存解决 Docker Hub/GHCR/Quay 可达性；缓存服务变化会影响重新拉镜像，但当前节点已有本次所需镜像。
10. PostgreSQL 使用 `dataDurability: required`；当没有同步副本可用时，写入会暂停以换取已确认事务的 RPO=0。
11. 测试机 15GiB 内存承载 3×4GiB VM，仅留约 3GiB 宿主余量，不作为生产容量基线。

