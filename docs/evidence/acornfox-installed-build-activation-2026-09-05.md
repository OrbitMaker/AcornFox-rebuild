# AcornFox installed build activation — 2026-09-05

Status: R1 code and Alibaba Git-worktree integration verified. This report does not
establish installation, upgrade, public HTTPS, or public release acceptance.
Owner: GPT-6 Astra, current control task. Development base: `26fc9a1b`.

## Scope and actual execution location

The clean server binds a distinct `build-execution` policy into its real delivery
service and requires live attestation of the installed rootless BuildKit worker.
The older source-specific self-build proof retains offline Dockerfile RUN steps.

Initial integration ran in the disposable devbox VM
`acornfox-r1-activate-20260905`. Following the user's explicit instruction, primary
execution moved to the authorized Alibaba ECS test instance. The current source
is pushed via SSH to a private server-side Git repository, with checkout at
`/srv/acornfox-work/checkout`; no GitHub credentials or private development Git
history were copied. The devbox VM has been gracefully shut down, with its disk
retained for evidence. Cloud snapshots are development inputs, not releases.

## Implemented boundary

- A fixed privileged network helper runs as a subcommand of the existing upgrade
  binary. It owns an initial-userns network namespace, scoped host firewall/NAT
  rules and a root-authenticated Unix attestation socket.
- The worker can fetch public HTTP/HTTPS dependencies through fixed public DNS.
  Private/reserved IPv4, cloud metadata, IPv6, other outbound ports, unsolicited
  ingress, the host's own public addresses and post-DNAT private destinations are
  denied. Rules never replace the host's default firewall policy.
- Before a build, attestation checks kernel rules, namespace ownership, veth
  identity, the actual BuildKit socket peer, executable, netns, cgroup and limits.
  The client command and socket must match the installed, attested worker.
- buildctl receives an isolated temporary HOME/Docker configuration and no ambient
  proxy/cloud/registry credentials. `BUILDKIT_NO_CLIENT_TOKEN=true` keeps registry
  bearer-token fetching inside the isolated daemon. This behavior was checked
  against the pinned BuildKit v0.32.2 source, independently reviewed and exercised
  with controller-user outbound HTTP/HTTPS explicitly rejected.
- The production worker uses Docker Official Images' public ECR namespace as a
  Docker Hub mirror, with normal HTTPS certificate validation and Docker Hub
  fallback. Availability of arbitrary public dependency sites is not guaranteed.

## Evidence collected before the cloud move

Raw evidence: `.omx/evidence/afb-build-03b-activate/`.

| Assertion | Observed result |
|---|---|
| Actual root attestation; installed policy tamper denied; restore accepted | PASS, 0.11 s |
| Eight denied destination/port classes | PASS, each backed by an increased nft counter |
| Worker userns cannot modify outer nft rules | PASS, EPERM |
| Host-owned public address and post-DNAT private destination | PASS, individual host nft counters |
| Actual administrator login and public Git source import | PASS |
| Real delivery API → OCI → durable build log → runtime task | PASS, 11.85 s; 2,236,416-byte OCI and 12,919-byte indexed log |
| Controller-user HTTP/HTTPS denied during that successful API build | PASS; zero attempted packets |
| Dockerfile installs dependencies and downloads with certificate-validating curl | PASS, RUN 47.3 s using the Alibaba Alpine mirror |
| Official Node image and Node/V8 build execution | PASS after measured service-policy fixes, RUN 5.5 s |
| Stop network owner removes its worker/network/rules; restart restores worker | PASS; control-plane process remained running |
| Cold-worker repeat of the same application | Local test exposed OCI export-time comparison; subsequent cloud verification is recorded below |

These live tests used the actual production manager and service units with a
**test-only manager carrier** and a test upgrade-safe target. The final stamped
privileged helper and real installation/upgrade path remain unaccepted.

## Defects found and repairs

1. Production configuration could attest one socket and execute another. Fixed
   by requiring the exact installed socket and buildctl command.
2. buildctl anonymous auth attempted to create `/nonexistent`. Each invocation
   now gets a fresh private HOME and removes it on exit.
3. Client-side registry token fetching bypassed worker networking. Disabled the
   client token authority so the isolated daemon performs anonymous token fetches.
4. Inherited systemd restrictions blocked runc's seccomp/hostname setup, fresh
   `/proc` mount, official image permission bits and V8 JIT. The worker alone has
   the necessary exceptions; its outer UID, initial-userns firewall and resource
   limits remain enforced. Other product services retain their hardening.
5. A repeat export had the same image manifest digest but a new
   `org.opencontainers.image.created` index annotation. The OCI store now compares
   all members and validates blob hashes before treating only that export-time
   difference as equivalent. It retains the original archive and its original
   evidence. Ambiguous JSON keys, path aliases and nonzero trailing archive data
   are rejected. Cloud repeated-build persistence subsequently passed, as recorded below.

## Verification and remaining work

Local focused Go tests, service/inventory checks, six installer-script tests and
`go vet` passed. The full local install suite exceeded its 10-minute default while
executing the large fsync-heavy fault matrix; it is not recorded as passed. The
full install suite is now running on Alibaba Linux. The initial cloud release-test
invocation lacked Node in PATH; the rerun uses the pinned task-local Node runtime.

Independent GPT-6 reviews approved the network/identity boundaries, subsequent
runtime exceptions, client-token fix and OCI comparison after two parser fixes.
Cloud execution, final candidate identity, safe upgrade, external HTTPS and public
publication remain separate acceptance steps.

## Final Alibaba R1 verification

Code tested in cloud snapshot `6a5e86f5cef3e67ce73366f9c34926058ad8ee3e`;
`a76d1d9545490544cfa8ea0a53a6851834f921a5` adds only the short Unix-socket
test-directory fix. Raw evidence: `.omx/evidence/aliyun-mvp-20260905/`.

- Fresh public Git import → actual delivery API → HTTP 202, OCI, this exact
  build's artifact and durable log: **PASS, 5.34 s**. Assertions join the caller
  request key, source, application, build, artifact and indexed log.
- Cold worker restart preserves the control-plane process; root attestation
  passes. Repeating a build with controller-user HTTP/HTTPS rejected persists
  its own artifact/log: **PASS, 3.76 s**, with zero controller web attempts.
  The test explicitly accepts the active-operation 409 at the later runtime
  stage because this fixture has no connected runtime Agent. It is **not**
  runtime deployment acceptance; the first fresh request above requires 202.
- Eight denied traffic classes, attempted rootless nft mutation, host-public
  alias and post-DNAT private address checks all passed on Alibaba. Temporary
  test rules and aliases were removed.
- Independent PostgreSQL regression: **PASS, 0.65 s**. Identical image digests
  and identical timestamps retain separate build artifacts; each release is
  bound to its own completed artifact. Artifact immutability and one-artifact
  per build remain enforced.
- The persisted fix is migration **0034**, not an edit to historical migration
  0008. Candidate migration/data compatibility now share the updated policy.
- Cloud source lookup uses explicit `223.5.5.5:53` and `223.6.6.6:53`: direct
  measurements showed `1.1.1.1` timing out on this host. The worker's closed
  DNS/egress policy remains unchanged, with its working `1.0.0.1` fallback.
- Core Go package tests and vet passed. The Unix test path was shortened after
  the secure task TMPDIR exposed the kernel socket-path limit. Updated install
  service/inventory/control-plane tests passed in **29.222 s**.

Remaining release-package blockers found by full cloud testing are tracked in
R2: cache/staging inode-reuse identity handling and the substrate lock replacement
case. Backup cases passed in 0.013 s after using a secure task TMPDIR; no backup
permission checks were weakened. Full install/release suites are not declared
passed while those R2 failures remain.

Independent GPT-6 review approved the final network/runtime exceptions, token
fetch boundary, OCI comparison parser, migration, release-to-artifact binding
and exact-request acceptance assertions. Formal candidate/stamped-helper,
installation, safe upgrade, runtime deployment, public HTTPS and publication
remain unaccepted.
