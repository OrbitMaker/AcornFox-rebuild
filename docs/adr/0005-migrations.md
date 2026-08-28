# ADR-0005: Forward-only checksummed SQL migrations

- Status: Accepted; core G5 Spike cases passing
- Gate: G5 / S1

Use ordered SQL files, SHA-256 checksums, a schema migration table, a PostgreSQL
advisory lock and one transaction per migration. Startup preflight rejects a
changed applied migration. Upgrades take a control-plane database snapshot
before mutation. Automatic down migrations are not supported.

The repeat, checksum-tamper, empty-to-latest, N-1-to-latest, failed-transaction
rollback and old-reader cases have executable tests. M7 must still prove the
snapshot/compatible-binary rollback path on a clean supported host.
