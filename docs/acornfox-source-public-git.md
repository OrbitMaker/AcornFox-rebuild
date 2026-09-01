# AcornFox public HTTPS Git source — AFB-SRC-01

Status: module and task-scoped integration evidence only. This leaf does not
claim host, external GitHub, customer, build, runtime, DNS, or public HTTPS
acceptance.

## User result

An administrator supplies a public HTTPS repository URL and a ref. AcornFox
resolves the ref to an immutable commit, creates an owned read-only workspace,
records its content digest, and returns an immutable `SourceRevision`. Once the
application result has durably completed, a retry with the same idempotency key
returns the original revision without fetching the remote again. The
pre-persistence crash window remains an outcome-reconciliation boundary. A new
key after the remote ref moves produces a distinct commit, digest, and workspace
while the first workspace remains unchanged.

## Reused implementation boundary

This leaf reuses `internal/providers/source.Provider` and
`application.Controller.CreateApplicationWithSource`; it adds acceptance tests
and no new production abstraction. The source provider requires two explicit,
agreeing public resolvers, pins the resolved authority, uses HTTPS only, rejects
redirects and system-resolver fallback, bounds clone/object material, disables
credentials and other Git protocols, and produces redacted evidence.

The application controller performs durable idempotency preflight before source
preparation. Therefore a recreated controller using the same durable repository
must replay an existing application/source result before it calls its fresh
source provider. If application creation reports failure after a real provider
published finalized content, the controller first checks for a durable replay
and otherwise returns the original error without deleting that content-addressed
workspace. This avoids deleting a workspace belonging to an outcome-unknown
commit or another immutable digest consumer. Provider Prepare removes transient
`.source-stage-*` and `.git-objects-*` directories; later reconciled GC, not
the application request, owns finalized workspace reclamation.

## Finite workspace admission

The provider admits new unique work only when its provider-owned workspace pool
has finite budget for the request. Zero configuration selects finite defaults;
negative, overflowing or one-public-Git-preparation-too-small values are
rejected at construction. Admission happens after same-key in-memory replay but
before DNS/TLS/Git work, under a provider-root cross-process lock. Public Git
reserves two conservative transient trees (bare objects and extraction stage);
uploads reserve one extraction stage. Usage charges every entry at least 4 KiB
and includes retained final digests plus crash-left transient trees. This is an
admission budget, not a filesystem quota.

Production can set the finite pool values with
`OPEN_CARD_SOURCE_WORKSPACE_CAPACITY_BYTES` and
`OPEN_CARD_SOURCE_WORKSPACE_CAPACITY_ENTRIES`, and its non-zero host reserve
with `OPEN_CARD_SOURCE_WORKSPACE_OPERATIONAL_RESERVE_BYTES` and
`OPEN_CARD_SOURCE_WORKSPACE_OPERATIONAL_RESERVE_ENTRIES`. Invalid, negative or
overflowing values fail server startup without echoing their value. Admission
requires both this provider-pool budget and actual filesystem available
bytes/inodes after the operational reserve; the effective cap is the tighter
of those two boundaries.

Finalized failed-create workspaces are retained for crash/data safety. Therefore
continued distinct failures eventually hit admission capacity and become an
availability tradeoff until later reconciled GC frees only proven-safe content.
There is no automatic cleanup or recovery claim in this leaf.

## Inputs and outputs

| Input | Result |
| --- | --- |
| canonical public `https://` repository URL, Git ref, application ID, idempotency key | immutable `SourceRevision`: fixed commit, content digest, provider-owned workspace reference and redacted evidence |

Repository locators must not contain credentials, query strings, fragments,
non-default ports, local/private targets, redirect targets or unsupported
protocols. Credential-bearing/malformed locators are rejected without the raw
locator or canary appearing in errors, details, or evidence references.

## Excluded scope

- Private Git Token or SSH Key, OAuth and Git push deployment.
- Source archive, OCI image and Compose inputs.
- BuildKit, runtime, health probe, logs, public domain/DNS/TLS and Web/API/CLI
  product wiring.
- External GitHub, clean-host and customer acceptance.

## Acceptance commands and evidence boundary

```bash
go test -count=1 ./internal/providers/source ./internal/application ./cmd/open-card-server ./internal/persistence/postgres
go test -race -count=1 ./internal/providers/source ./internal/application
OPEN_CARD_AFB_SRC_TEST_DATABASE_URL=postgresql://... go test -tags=integration -count=1 ./internal/providers/source -run '^TestAcornFoxPublicGitDurablePostgresComposition$'
OPEN_CARD_AFB_SRC_TEST_DATABASE_URL=postgresql://... go test -tags=integration -count=1 ./internal/providers/source -run '^TestAcornFoxPublicGitDurablePostgresComposition$'
go test -tags=integration -count=1 ./internal/persistence/postgres -run TestG3SourceUploadPersistsAndApplicationClaimIsAtomic
```

The `internal/providers/source` integration command is the decisive public-Git
composition evidence; the narrower PostgreSQL test uses a deterministic fake
Git preparer and is retained only for store behavior. Both commands require a unique loopback task database via
their respective named environment variables. The decisive source test requires
`OPEN_CARD_AFB_SRC_TEST_DATABASE_URL` with database prefix `open_card_afbsrc_`;
it resets only that validated dedicated schema before applying migrations, so
the same DSN must pass twice sequentially. An unset DSN is a skipped test, not
integration PASS. Git acceptance uses only the package-local TLS fixture and
test CA. It does not contact GitHub or any public remote.
