# ADR-0004: PostgreSQL 16 control-plane database

> 2026-09-26 scope update: the user selected SQLite for the new AcornFox single-machine thin core. The PostgreSQL choice below is historical and remains relevant to existing installations and migration evidence. See the [migration plan](../acornfox-rebuild-migration-plan.md). SQLite implementation and migration acceptance are pending; this does not authorize deleting old data.

- Status: Accepted; G4 Spike passed
- Gate: G4 / S1

Use a single PostgreSQL 16 instance with transactions, constraints and bounded
JSONB. PostgreSQL 16 remained upstream-supported when this ADR was recorded and
was already locally cached on the development host, allowing a digest-pinned,
task-isolated Spike without changing host packages. The Spike container is
loopback-only and resource-limited; it is not production evidence.

`SPIKE-S1-POSTGRES-REPOSITORY` passed transactional business/outbox creation,
20-way idempotency, process-store task lease takeover and 100,000-event query
p95 of 9.58 ms. `FAULT-DB-001` passed kill/WAL recovery, absence of partial
business/outbox state and idempotent publication. PostgreSQL therefore remains
the selected implementation; the SQLite fallback was not invoked.
