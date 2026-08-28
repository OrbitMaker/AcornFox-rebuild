# M6 deterministic rules

`Registry` is the reviewed-rule composition boundary. `NewLocal()` provides
an in-process implementation and `NewPostgres(db)` persists immutable facts
through migration `0021_m6_controlled_ai.sql`.

Candidate lifecycle is deliberately one-way:

`draft -> testing -> reviewed -> shadow -> approved -> promoted`

Promotion requires the minimum evidence gate (two successful observations
covering one application), a reviewer/decision, regression evidence, a
proposed version, and a passed shadow result. Candidate records never become
an `active` state. Repeated observations after a promoted candidate create a
new candidate for the same fingerprint, preserving the prior version.

`Promote` creates an immutable `RuleVersion`; `Enable`, `Disable`, and
`Rollback` append registry events. `Active` resolves the latest event, so no
method edits core code or hot-updates a live rule body. A second active version
is rejected until the current version is disabled. `Metrics` reports candidate
states, version/rollback counts, and observed successes.
