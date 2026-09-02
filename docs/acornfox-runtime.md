# AcornFox 单服务运行时

`AcornFoxRuntimeDriver` 是单机交付层的一个窄适配面：它把一份已接受、不可变且只含一个服务镜像的 Release 交给既有运行时 Provider。它不管理 Docker，也不提供集群编排、数据卷、回滚、扩缩容或对外发布能力。

## 输入与资源边界

`ProjectAcornFoxRuntimeReleaseFact` 只接受状态为 ready 的不可变 Release，并且该 Release 只能有一个服务镜像。事实固定绑定应用、环境、Release、服务、镜像摘要、容器端口和以下请求资源：CPU、内存、PID 与磁盘预留。

适配层内部才将请求资源投影为旧 `RuntimeSpec`：CPU、内存、PID 与磁盘预留会传给既有 Provider；旧的超时和并发槽字段始终为零，不属于 AcornFox 对外契约。

Docker 可读回的应用限额仅为 CPU、内存与 PID。磁盘结果明确表示为：`reservation_bytes`、`accounting_reconciled=false`、`per_container_enforced=false`。因此磁盘预留不是单容器磁盘限制，也尚未证明容量账本已对账；容量预留与对账接入前仍是 Provider/容量模块的依赖。

运行时只接受零或一个容器端口。端口存在时只能绑定到 `127.0.0.1:宿主端口:容器端口/tcp`。没有任何公网入口声明。

## 生命周期与幂等

公开方法只有 `Deploy`、`Observe`、`Restart`、`Destroy`。每个变更请求都有调用方提供的非空 `idempotency_key`，该值保留在 AcornFox 请求边界。适配层传给 Provider 的键则由不可变事实、动作和调用方键稳定导出：同一事实、动作和调用方键得到同一 Provider 键；不同动作、事实或调用方键得到不同 Provider 键。因此同一个调用方键不会在 Deploy、Recreate、Restart 与 Destroy 之间串用。

`recreate=true` 只会调用 Provider 的单个原子 `Recreate` 操作。适配层不会先 Destroy 再 Deploy，也不会把“未找到”伪装成成功。Restart 与 Destroy 均返回 Provider 的类型化结果。

Provider 重启后的容器接管、幂等记录和持久状态仍需要 Provider 的耐久实现与独立验证；本适配层不声称已经提供这些能力。

## 可观察事实

Observe 返回容器运行状态、重启计数、容器 ID、请求资源、Docker 读回的 CPU/内存/PID 限额和上述磁盘事实。它不读取或传播容器 `Healthy` 业务就绪状态：容器正在运行不等于应用已经响应。

带端口时只返回 `127.0.0.1:端口` 形式的内部地址。这只说明本机回环绑定，不表示公网可访问或业务已经健康；应用响应检查属于后续独立探测阶段。
