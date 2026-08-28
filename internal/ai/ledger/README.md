# M6 AI ledger

`ledger.Repository` is the composition boundary for controlled-AI evidence.
Use `NewLocal()` for deterministic tests or process-local fallback and
`NewPostgres(db)` with the control-plane `*sql.DB` for durable operation.

The explicit append methods checkpoint individual phases:

- `AppendInvocation`
- `AppendContext`
- `AppendPlan`
- `AppendToolAction`
- `AppendVerification`
- `AppendRollback`
- `AppendOutcome`
- `AppendCandidateRef`

`AppendIntervention` atomically records a complete run. Every request carries
an idempotency key and request digest; a same-key/same-digest call returns the
committed record with `replayed=true`, while a different digest returns
`ErrConflict`. `Snapshot`/`NewLocalFromSnapshot` provide local restart replay.

`ValidateNoPlaintext` rejects sensitive values rather than silently changing
evidence. Store references or digests (`secret://`, `ref:`, `sha256:`) and
`[REDACTED]`; never pass prompts, raw logs, credentials, or provider response
bodies.

AI settings use `AppendSettings`/`CurrentSettings`. Profiles are strictly
`mainland`, `global`, `local`, or `disabled`; disabled settings cannot enable a
provider, and `external_calls` is always false. The settings event is a
versioned configuration fact, not a credential store.
