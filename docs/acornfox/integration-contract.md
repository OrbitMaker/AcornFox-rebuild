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
and migrations 0035 through 0039. Fresh installations leave the optional worker disabled.
Same-schema upgrade and rollback preserve its prior enabled state. A predecessor with
a different database migration version is rejected before upgrade effects; cross-schema
migration is not implemented by this path.

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
