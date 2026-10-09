# 架构说明

## 文档边界

本文只描述并约束已经验证的 k3s/Open-Local/Higress/CloudNativePG/Prometheus 基础设施 PoC，不是 Open Card MVP 产品架构，也不包含 AI 产品架构。

## 决策

### k3s 而不是 kubeadm

节点只有 4C/4GiB，k3s 的控制面和默认运行面更轻。安装时禁用 Traefik 和 ServiceLB；Higress 通过固定 NodePort 暴露局域网入口，避免云负载均衡依赖和 80/443 宿主端口争用。

### Open-Local 使用独立数据盘

每台 VM 的 50GiB 拆分为 30GiB 系统盘和 20GiB 数据盘。Open-Local 只管理数据盘创建的 LVM VG。这样既满足单节点 50GiB 约束，又把本地 PV 初始化限制在可验证的独立设备上。

本地 PV 的故障域是节点。Pod 重启可以保持数据；节点宕机时，卷不会自动迁移到其他节点。这是 Open-Local 的设计边界，不等同于 Longhorn 的多副本存储。

### 单控制面

`node-dev-01` 同时承担 k3s server 和可调度 worker。它验证控制平面与工作负载闭环，但不提供控制面 HA。工作节点故障可由 Kubernetes 恢复；控制平面宿主故障会导致 Kubernetes API 不可用。

### PostgreSQL

CloudNativePG 管理 1 Primary + 2 Replica。三个实例各用独立 PVC，不共享 PGDATA。同步复制和 failover 能减少故障窗口，但在本地 PV 方案下，节点级永久丢盘仍超出本阶段承诺。

### 资源策略

- 普通应用最多 3 副本。
- Higress 控制面和网关使用 PoC 低资源 values，网关默认 1 副本。
- Prometheus 单副本、2 天保留期；不安装 Alertmanager。
- 所有仓库内业务 workload 都必须设置 requests/limits。
- 每阶段验证节点压力和 OOMKilled 状态，出现压力后停止进入下一阶段。

## 数据流

```text
LAN client
  -> Higress ServiceLB / Ingress
  -> demo-web Service
  -> 3 demo Pods
  -> CloudNativePG read-write Service
  -> PG primary / replica WAL replication

Prometheus
  <- node-exporter / kube-state-metrics / kubelet
  <- CloudNativePG PodMonitor
  <- Higress metrics ServiceMonitor
```

## 自动化边界

`install.sh` 是总入口，Make target 是阶段入口。宿主机访问参数保存在 gitignored 的 `config/inventory.env`；kubeconfig、token 和运行证据保存在 gitignored 的 `artifacts/`。部署脚本必须可重复执行，并在前置条件不满足时停止。
