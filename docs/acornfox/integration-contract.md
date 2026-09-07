# Console and assistant integration

The console preserves the 18 existing AcornFox API response contracts. Additional setup,
host, source, operation, assistant, and action endpoints are declared in
`api/openapi/acornfox.yaml`; `npm --prefix web run test:acornfox-parity` checks the
CLI and both browser clients against that inventory.

## Installation and host facts

The public setup endpoint creates the first administrator using the root-provisioned,
single-use setup credential. Any existing administrator row closes setup permanently.
It does not create a login session or provide public registration.

Host metrics are authenticated, sampled on Linux every five seconds, and expire after
15 seconds. CPU and network rates require two valid samples. Unsupported, warming,
and stale values remain unavailable rather than becoming zero.

Source repository URLs require explicitly recorded public Git provenance. Deployment
source details follow the exact release/build/source linkage. Source updates import a
new immutable revision; they do not deploy it. Operation results refer to the exact
requested operation and require independent execution evidence for verification.

## Assistant ownership

The browser talks only to Go. Go owns authentication, immutable session scope,
durable messages and events, idempotency, cancellation, and execution policy. The
independent unprivileged worker runs pinned Pi 0.85.1 over stdio RPC, using DeepSeek
`deepseek-v4-flash` with thinking disabled. Its model key is a systemd credential.
See `assistant-operations.md` for root configuration commands.

A revocable per-run capability grants access to the protected Unix tool socket.
The trusted extension exposes factual host/application/source/deployment/log/operation
reads and a controlled HTTP probe. A separate read-only tool returns administrator-client external-access observations, preserving their reported provenance and expiry. It also prepares restart and redeploy proposals.
There is no generic shell tool and no model-accessible approval endpoint.

A user confirms a proposal through the authenticated console. Go revalidates the exact
target and uses one persistent execution key. An uncertain acknowledgement remains
unknown; recovery checks the original action instead of creating a replacement.
Verification establishes the requested operation fact, not overall application health.

Messages survive page navigation and panel collapse. Reconnecting replays SSE events
without posting another prompt. The default global concurrency is one; queued work
remains accepted. Process restart marks unfinished runs unknown rather than replaying
them. Completed replies replace their transient deltas in bounded event retention.

## Release boundary

The candidate includes the complete pinned Pi resource tree, worker, trusted extension,
and the closed control-plane migration set. Fresh installations leave the optional worker
disabled. Same-schema upgrade and rollback preserve its prior enabled state.

Cross-schema upgrade is limited to the two authenticated predecessor pairs 0034 to 0040
and 0039 to 0040. The 0034 path first verifies the historical six-account receipts and
the strict absence of Pi state, then journals creation of the separate Pi account and
fixed private data directories. The 0039 path verifies its frozen seven-account package,
runtime, database, and optional-worker receipts without provisioning another account.
Unknown account or unit state fails closed.

Both paths verify an exact checksum-contiguous source migration prefix, stop internal
services behind the upgrade marker, write a root-private custom-format PostgreSQL dump,
restore it into a transaction- and binding-derived shadow database, and execute only the
remaining migrations. The old database is retained unchanged. Candidate database health
and an isolated candidate server `/healthz` and `/readyz` check must pass before activation.
Only a terminal, current-repository-bound upgrade journal authorizes normal runtime and
administrator helpers to read the shadow database environment. Failure or fresh-process
recovery switches files and `database.env` back to the predecessor, restores the captured
optional-worker intent, and keeps ingress blocked until the predecessor is healthy.
For 0039 predecessors with an assistant key, the private journal binds the exact 13-tool
and 15-tool worker configurations plus the key digest. Activation atomically updates only
`worker.json`; rollback restores the old configuration, while the model key file remains
unchanged.

Candidate/source checks, local tests, target-host installation, application public access,
and public release acceptance are separate evidence layers. A manually staged console
or successful model call does not establish full installed-release acceptance.

## External access observations

An administrator can run `acornfox public-access check APP_ID DEPLOYMENT_ID` on an
external machine. The CLI reads the server-derived public URL, resolves public IPs,
checks standard TLS for the exact hostname, then reads at most a 64 KiB HTTPS response
sample. It follows no redirects and sends no session cookies to the application.
The lookup and probe phase has a 30-second deadline; report submission has its own
10-second deadline so a timeout result can still be recorded. `public-access observation` only
reads the stored report.

Reports record the administrator identity, exact deployment and hostname, observation
and receipt times, a five-minute expiry, layer-specific outcomes, and prefixed SHA-256
fingerprints. They report the administrator client's measurement, not proof of a
third-party observer location. Identical report retries return the original timestamps;
expired reports cannot refresh their own validity. A deployment that has not enabled
public access returns no current observation. The old public-access DTO retains its
local routing meaning.

## Application fix candidates

The fix-candidate lane is separate from immutable source intake and normal delivery.
It never edits a `SourceRevision`, assigns a Git commit to local changes, writes a
normal Build/Release/Deployment row, or changes a running application. Its additive
ledger records bounded candidate and verification facts without changing the existing
18 AcornFox response contracts.

Phase 1 reads an exact application-owned public-Git `SourceRevision` from its existing
read-only workspace. The source provider rechecks the persisted tree digest before and
after copying into a private candidate directory below the configured source workspace
root. Model context contains only an explicit allowlist of at most 32 ordinary text
files, and Assistant source reads fail closed when the application has any active secret
reference. A proposed unified diff is limited to 128 KiB and 32 paths. Fixed Git argv reads
the diff from stdin; no shell or caller-selected executable is available. Binary,
rename, copy, mode, symlink, hardlink, absolute, traversal, `.git`, credential and
sensitive-file changes fail closed. The resulting tree is rehashed, made read-only and
represented as a transient `candidate://` source with no Git commit. BuildKit validates
that transient source through the existing AcornFox Dockerfile binder, trusted network
policy, capacity lease, bounded logs and immutable OCI store. Candidate build facts do
not enter the normal build/release tables.

Phase 2 sends only a digest-bound candidate runtime request through the existing Agent
task envelope and a dedicated capability marker. The Agent uses a separate candidate
runtime provider below its configured runtime work root, a fixed task prefix and an
internal Docker network. It accepts no volumes, secrets, Caddy route, host path, command
or shell. Success requires exact OCI readback, bounded runtime observation, loopback
probe evidence, destroy completion and independent confirmation that the candidate
container is absent. Cleanup failure keeps the candidate unverified.

Phase 3 exports the canonical diff and evidence receipt for administrator review. The
platform never pushes Git. After the administrator commits the change and supplies a
public ref, W05 imports that ref from the same canonical repository into a new immutable
`SourceRevision`. The candidate may enter the existing delivery path only when the
imported tree digest equals the sealed candidate tree digest and a release-time build
produces the same OCI image digest that runtime validation used. Repository or tree
mismatch remains an imported source fact but cannot be presented as the verified
candidate or trigger candidate delivery.

The internal seams are intentionally small: a candidate workspace manager performs
bounded reads/apply/seal/export; an application service owns idempotency and state; the
existing BuildProvider performs the build; a candidate runtime validator owns the Agent
task; and the existing W05 service performs the only Git ref import. Normal source,
delivery, assistant and M6 fake-runner behavior remains outside this lane.

Candidate creation is asynchronous. The server reserves a stable candidate identity and
returns `202 preparing` before entering a single-worker, eight-item queue; each item has a
20-minute execution deadline independent of the HTTP or Pi callback deadline. Owner-scoped
item reads and the latest-50 list expose `preparing`, `failed`, `validated`, and
`source_matched` facts. Request cancellation after durable acceptance does not cancel the
job. Graceful shutdown cancels and joins candidate work; startup converts any preparing row
left by a crash into failed, so an interrupted build can never appear validated. An expired
source-matched candidate can only replay a completed publish receipt for the same candidate
and client key; a missing receipt cannot reserve work or bypass expiry.

One server owns candidate execution through a dedicated PostgreSQL session advisory lock.
Every candidate state mutation uses that same session, so loss of the leader connection
fences completion immediately; a pool connection cannot write a stale validated result.
Other server instances remain read-only for candidate item and list discovery.
