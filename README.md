# Open Card 云原生基础设施 PoC

本仓库只验证一条本地 IDC 基础设施链路：

`物理机 -> libvirt VM -> k3s -> Open-Local -> Higress -> Demo/CloudNativePG -> Prometheus`

本阶段不包含 SaaS 控制台、用户、支付、计费、多租户、AI Agent、云 API 或应用市场。

## 目标拓扑

| 节点 | 所在宿主 | 角色 | 规格 | 磁盘 |
| --- | --- | --- | --- | --- |
| `node-dev-01` | 开发机 | k3s server + 可调度 worker | 4C/4GiB | 30GiB OS + 20GiB local PV |
| `node-test-01` | 测试机 | k3s agent | 4C/4GiB | 30GiB OS + 20GiB local PV |
| `node-test-02` | 测试机 | k3s agent | 4C/4GiB | 30GiB OS + 20GiB local PV |
| `node-test-03` | 测试机 | k3s agent | 4C/4GiB | 30GiB OS + 20GiB local PV |

每节点总磁盘 50GiB。独立的 20GiB 虚拟块设备用于 LVM/Open-Local，避免在系统根盘上做破坏性切分。

## 严格执行顺序

```text
preflight -> VMs/k3s -> storage -> OpenKruise -> Higress -> Demo -> PostgreSQL -> monitoring -> drills
```

管理机前置命令：`ssh`、`kubectl`、`helm`、`curl`、`openssl`。两台 Linux 宿主需要 KVM/libvirt、`virt-install`、`qemu-img` 与 `cloud-localds`；预检会一次性核对这些条件。

完整安装：

```bash
cp config/cluster.env.example config/cluster.env
# 按现场填写两台宿主和 VM 的 SSH 私钥路径；cluster.env 不入 Git
./install.sh
```

分阶段执行：

```bash
make preflight
make kubernetes
make storage
make openkruise
make higress
make demo
make postgres
make monitoring
make drills
```

每个阶段先安装再验证，日志和快照写入 `artifacts/<phase>/`。`artifacts/` 是现场证据，不保存凭据。

## 版本基线

- k3s `v1.34.10+k3s1`
- Open-Local `v0.7.1`
- OpenKruise `v1.9.1`
- Higress `v2.2.4`
- CloudNativePG `v1.30.0`
- kube-prometheus-stack Helm chart `88.5.2`

版本均被脚本固定，升级必须作为单独阶段重新验证兼容性。

## 验收入口

- 架构和边界：[docs/architecture.md](docs/architecture.md)
- 验收矩阵：[docs/acceptance-matrix.md](docs/acceptance-matrix.md)
- 故障演练报告：[docs/fault-drill-report.md](docs/fault-drill-report.md)
- 已知问题：[docs/known-issues.md](docs/known-issues.md)
- 下一阶段建议：[docs/next-phase.md](docs/next-phase.md)

## 当前现场状态（2026-08-21）

第一阶段已全部通过。局域网入口：

```bash
curl -H 'Host: open-card.local' http://192.168.31.71:30080/
curl -k --resolve open-card.local:30443:192.168.31.71 https://open-card.local:30443/
```

管理集群：

```bash
KUBECONFIG="$PWD/artifacts/kubeconfig" kubectl get nodes -o wide
make verify
```

Grafana 与 Prometheus 保持 ClusterIP，仅通过 `kubectl port-forward` 在管理机本地查看，未暴露公网。

## 安全边界

- 不删除旧 Sealos VM、磁盘或快照。
- 若需要释放测试机资源，只允许对脚本中明确列出的旧测试 VM 执行优雅关机并取消 autostart。
- 不在 Git 中保存私钥、kubeconfig、k3s token、Grafana 密码或数据库凭据。
- 所有磁盘初始化只允许命中 VM 内独立的数据盘，禁止对宿主盘和 VM 根盘执行 `pvcreate`/`wipefs`。
