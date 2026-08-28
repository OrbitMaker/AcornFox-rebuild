# ADR-0006: PostgreSQL aggregates and bounded local logs

- Status: Accepted; G6 / S4 Spike passed
- Gate: G6 / S4

Store raw metric observations and UsageAggregate rows in partitioned control-
plane tables. Store build/runtime logs in local rotating files with database
indexes, and audit evidence in append-only tables outside ordinary log GC.

The initial Spike workload is 100 services, seven days, one-minute samples
(1,008,000 rows), five-minute aggregates, and p95 query latency at most 500 ms.
Initial retention/limits are raw metrics seven days, runtime logs 10 MiB times
five per service, the latest 20 build logs, a 5 GiB task-log hard limit, and
80%/90% disk soft/hard watermarks. `SPIKE-S4-OBSERVABILITY` inserted 1,008,000
task-isolated samples and measured twenty five-minute aggregation queries at
p95 71.30 ms; the 504 MB temporary database was removed after the run.
`SPIKE-S4-LOG-STORE` proves pre-write secret redaction, rotation, latest-20
build retention, runtime retention, total-byte GC, restart recovery and audit
exclusion. Soft/hard host watermarks remain an M4 operational integration.
