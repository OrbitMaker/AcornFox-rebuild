# Open Card M4 基础运维 fixtures

这是 M4 批准测试规格的最小、确定性、数据-only fixture 集。它覆盖
Observation、日志脱敏/轮转/保留、最小影响运维操作、Webhook 签名/去重/重试、
SSRF 拒绝和证据门禁。

## 隔离与安全边界

- 仅使用 `.test` 逻辑身份、`127.0.0.1` receiver 和任务 VM 内部服务；不访问公网。
- Webhook 签名只引用 `secretprovider://m4/webhook-fixture-signing-key`；签名向量使用 fixture-only 测试 key，目录中没有真实密钥。
- `redaction-inputs.json` 中的值是明确标记的测试 canary，不是凭证；编码变体只用于脱敏测试。
- SSRF 用例包含 localhost、loopback、metadata、RFC1918 和 IPv6 link-local，均应在发起请求前拒绝。
- fixture 不代表真实外部通知已发送，也不替代 DB、Docker、Agent、Caddy 或故障注入的真实证据。

## Fixture index

| Path | 用途 |
| --- | --- |
| `operations/app-restart-rollback.json` | 异常服务选择性重启、重新部署失败、上一成功 Release 回滚和数据卷不回滚提示。 |
| `operations/active-operation-conflict.json` | 同一环境并发 active Operation 的唯一约束冲突。 |
| `observability/observation-samples.json` | CPU/内存/磁盘/网络/restart 的固定样本与独立测量期望。 |
| `logs/redaction-inputs.json` | Token、密码、Cookie、known-key 及 base64 变体脱敏。 |
| `logs/rotation-retention.json` | 单文件轮转、21 次构建保留最近 20 次、审计不被普通 GC 删除。 |
| `webhook/vectors.json` | HMAC、时间戳、event ID、错签名、过期和重放向量。 |
| `webhook/ssrf-cases.json` | Webhook 目标 SSRF 负向用例和 loopback 测试 receiver 声明。 |
| `runtime/receiver-responses.json` | 200、timeout、500、恢复后的有限重试与去重响应。 |
| `evidence/required-layout.json` | M4 证据目录、必需文件和 evidence-insufficient 负例。 |
| `manifest.sha256` | 除 manifest 外全部 fixture 的 SHA-256 清单。 |

## 规格映射

主要映射为 `UNIT-REDACT-001`、`UNIT-WEBHOOK-001`、`SCHEMA-OP-001`、
`CT-NOTIFY-001`、`LOG-INT-001`、`WEBHOOK-INT-001`、`OPS-E2E-001/002`、
`SEC-SECRET-001`、`SEC-LOG-001`、`SEC-WEBHOOK-001/002`、
`VOL-FAULT-001`、`FAULT-WEBHOOK-001`、`OBS-001/002`、`LOG-001/002/003`。

运行器必须将每个测试的独立证据写入
`artifacts/mvp/m4/<test-id>/`，严格合并 M0-M4 JUnit；缺少必需证据、只有
HTTP 200、或只有容器存在都不得标记 PASS。
