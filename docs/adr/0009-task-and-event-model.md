# ADR-0009: PostgreSQL outbox and leased task queue

> 2026-09-26 scope update: the new single-machine thin core targets SQLite. The behavioral guarantees below remain required; PostgreSQL locking SQL is not the target implementation. See the [thin-core migration plan](../acornfox-thin-core-migration-plan.md) for serialized short writes, durable execution generations, transactional outbox and migration. Historical PostgreSQL test results do not establish SQLite acceptance.

- Status: Accepted; G9 Spike passed
- Gate: G9 / S1

Use the same PostgreSQL transaction for business state and append-only outbox
events. Use database-backed tasks with leases, one active Operation per
environment, unique idempotency keys and monotonic aggregate sequence numbers.
Do not add Kafka or another queue to the self-deployed MVP.

Initial parameters are 30-second leases renewed every ten seconds, batch size
100, 250 ms idle polling, three attempts, and 1/2/4-second backoff with jitter.
Out-of-order Agent facts cannot move aggregate versions or sequences backward.
Transactional creation, 20-client idempotency, expired lease takeover across a
new Store, renewal, 100 duplicate submissions and replay all have repeatable
evidence. `SPIKE-S1-CONTROLLER-WORKER` additionally proves Task/Operation/
Deployment/outbox transaction boundaries, sequence-gap/conflict rejection,
exact terminal-result replay, three-attempt exhaustion, failure redaction,
process-store takeover, durable Agent dispatch/result bridging and rollback
convergence. Installed-process transport compatibility remains tracked under
G2/G8 rather than weakening this database/controller result.
