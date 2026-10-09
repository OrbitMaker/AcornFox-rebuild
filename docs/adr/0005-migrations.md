# ADR-0005: Forward-only checksummed SQL migrations

> 2026-09-26 scope update: new single-machine installations target SQLite . Preserve the forward-only/checksum/recovery requirements below, with a separate SQLite migration inventory and equivalent exclusive migration ownership. Existing PostgreSQL migrations and checksums remain unchanged. Cross-engine migration and post-cutover recovery require new evidence.

- Status: Accepted; core G5 Spike cases passing
- Gate: G5 / S1

Use ordered SQL files, SHA-256 checksums, a schema migration table, a PostgreSQL
advisory lock and one transaction per migration. Startup preflight rejects a
changed applied migration. Upgrades take a control-plane database snapshot
before mutation. Automatic down migrations are not supported.

The repeat, checksum-tamper, empty-to-latest, N-1-to-latest, failed-transaction
rollback and old-reader cases have executable tests. M7 must still prove the
snapshot/compatible-binary rollback path on a clean supported host.
