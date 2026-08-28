# Open Card M5 用量 fixtures

这是 M5 用量与分析底座的确定性、数据-only fixture。所有时间戳为 UTC，窗口
采用半开区间 `[from,to)`，默认桶宽为 300 秒。样本代表独立
Observation/Metric 事实；`expected-aggregates.json` 是由固定样本手算得到的
对照值，不是从产品数据库导出的结果。

fixture 覆盖：

- `UNIT-USAGE-001`：平均、峰值、趋势和 CPU/内存积分聚合；
- `CT-METER-001` / `USAGE-001`：稳定 sample identity、重复样本、乱序及迟到样本；
- `USAGE-002`：application/service/release/time 过滤与应用隔离；
- `USAGE-003`：配置上限和实际用量分栏，不能互相覆盖；
- `USAGE-INT-001` / `E2E-USAGE-001`：从独立观察事实到可查询摘要；
- 原始保留、聚合保留和磁盘水位下的审计/最新摘要保留。

本目录只含本地用量事实、配置限制和聚合对照，不含外部服务凭据、用户数据或
任何交易相关字段。manifest 必须覆盖除自身外的每个普通文件；测试会校验摘要、
时间语义、应用边界和禁止字段。
