# Gate5B RC0-to-RC1 atomic upgrade acceptance — internal PASS

Date: 2026-08-31

Gate5B is accepted for the **internal clean-Ubuntu boundary**. The same locally
verified RC1 candidate passed both the complete stateful success path and a
real process-kill plus host-reboot rollback path. This is not a production
release, public DNS/ACME, or customer-deployment acceptance record.

## Candidate and predecessor binding

- RC1 product source: `a23ec9024a176cb0d00784a64aaf10a97fc4d1c4`.
- Candidate: `0.8.0-rc.1`, `amd64`, migration `0024`.
- Release manifest entries: 68.
- Archive members: 69; no unsafe path and no symlink member.
- Build metadata continues to declare `production_accepted=false`.

| Artifact | SHA-256 |
| --- | --- |
| `release/manifest.json` | `57271339953ece13c64ea80b6db5cc045005c104f942ca9e95f9e705dd3cf7fa` |
| `open-card-0.8.0-rc.1-production.tar.gz` | `7eb268c1becfc7a61564a87b6a6132c988a567f7be5d1d66ec31427a45f7a46a` |
| `bundle-manifest.sha256` | `15f667fca1ba4240fc5fa87ab42fd5c16c42e76e431058d88b6c76a2f4df5214` |

The candidate embeds the exact frozen RC0 predecessor facts:

- version `0.8.0-rc.0`, migration `0023`;
- source `35a2b198ac52949af3477475d89d4813b46a9490`;
- release manifest
  `3b3953c0a26f8706151583ad6c9cad6b5502da18b28f11ed66ca92fe604aa253`;
- archive
  `abc034ed24e8e8dc74b8eabc84dd3071a66f166abe65135502911e9153c0b9fc`;
- bundle manifest
  `960ab65526b890009e1770ad190a70b1589f825e0f59cf8d757634a0a8848392`.

The candidate build record binds runtime-input manifest SHA-256
`e06b81640a1225029ec0f548a22a05bb0d9957a8207f3347830a14c80973ef8a`
to the source and artifact identities above.

## Clean-Ubuntu success path

Raw ignored evidence: `.omx/state/g5b-product-a23e-success7`.

- Product source: `a23ec9024a176cb0d00784a64aaf10a97fc4d1c4`.
- Harness commit: `b48a5dcab14f48d08be80fb99486d6d7e33a9aeb`.
- Fresh Ubuntu 24.04 amd64 guest, 4 vCPU, 8 GiB class memory, 100 GiB thin
  overlay, task-only NAT network, no host port forwarding, autostart disabled.
- The real production wrapper projected the pinned RC0 split layout, retained
  its 23 migration rows, restored into a distinct candidate database, applied
  migration 0024, validated the candidate, and finished `COMMITTED`.
- A pre-upgrade sentinel was present in both old and candidate databases.
- The active activation was native RC1/0024; the previous activation remained
  the RC0 compatibility projection.
- The runtime and upgrade PostgreSQL roles retained their intended privilege
  split.
- V2 backup creation, mutation after backup, restore into a fresh activation
  and database, and restored sentinel verification passed.
- A real ACPI reboot changed the boot ID. Server, Agent, rootless BuildKit,
  loopback Caddy, Edge, readiness, socket, active activation, and restored data
  passed afterward; the upgrade marker remained absent.
- `console.localhost` kept certificate work on Caddy's internal boundary. The
  run rejected any Let's Encrypt or ZeroSSL log evidence.

The guest evidence manifest contains 29 entries and independently reverified.
Its SHA-256 is
`730beeff5d9809b22e2aef432da71f1a6bd098e0e0b68d52b04426303449a223`.

## Active-switch kill and reboot rollback

Raw ignored evidence: `.omx/state/g5b-product-a23e-active-crash7`.

- Product source: `a23ec9024a176cb0d00784a64aaf10a97fc4d1c4`.
- Harness commit: `245cbbebce239c0f84d67b335c72ad5682c50a86`.
- The harness invoked the real production wrapper. After the journal reached
  `MIGRATED`, it stopped the exact helper, armed an active-pointer watcher,
  resumed the helper, and sent `SIGKILL` only after `active` became the native
  candidate.
- Before reboot, raw evidence records candidate `active`, legacy
  `previous-active`, journal state `VALIDATED`, and the marker retained.
- A real ACPI reboot changed the boot ID.
- Early boot reconciliation restored the RC0 activation, retained the native
  candidate as `previous-active`, and persisted
  `ROLLBACK_SWITCHED -> ROLLED_BACK` with failure code `boot_recovered`.
- Finalization restored the old server and Edge through their immutable RC0
  liveness contracts, removed the marker, and completed successfully.
- Manifest-bound raw facts record the RC0 sentinel value
  `rc0-before-upgrade`, the retained candidate database identity and 24
  migration rows, the final old/candidate pointers, marker absence, active
  Edge, and absence of Let's Encrypt/ZeroSSL log evidence. No old or candidate
  database was automatically dropped.
- The evidence tree contains no DSN, password, private key, or credential
  material.

The guest evidence manifest contains 21 entries and independently reverified.
Its SHA-256 is
`6599d4ffc886a3629b4b436ea06a0ac631971e13775979538ed03e3880b8a289`.

The success summary's scenario-local `crash_failure_matrix=PENDING` line is
superseded by this separately bound crash run; the original evidence file is
left unchanged.

## Other accepted failure and boot evidence

- `tests/integration/install/gate5b_task_pg_test.go` passed nine real,
  task-scoped PostgreSQL scenarios: success, snapshot failure, restore/create
  failure, migration failure, validation failure, active-switch failure,
  post-switch health failure, unknown outcome with repeated recovery, and lock
  plus candidate-evidence rejection. Old and candidate databases were retained
  according to policy.
- `docs/evidence/gate5b-boot-graph-proof.md` separately proves the real Ubuntu
  systemd required/Wants graph, marker gating, prepare/finalize failure
  propagation, reboot behavior, and absence of public listeners while guarded.

## Final verification

- `go test -count=1 ./...`: PASS.
- `go test -race -count=1 ./...`: PASS.
- `go vet ./...`: PASS.
- G5 production-build, G2 production-bundle and installer-security Python
  suites: 28/28 PASS.
- All relevant MVP and Gate5B shell files pass `bash -n`.
- `git diff --check`: PASS.
- Independent code and evidence review found no remaining internal blocker.

Both final evidence roots passed their recorded `manifest.sha256`, recursive
secret scan, and exact cleanup checks. On the fixed development host, the exact
a02 domain, network, pool, task root, claim, and `virbr-g5ba02` bridge were
absent after each run. No legacy a01 resource was touched.

## Remaining release and external boundary

Gate5B's internal code and environment acceptance is PASS. The following are
still deliberately **PENDING**:

- publishing or declaring the candidate production-accepted;
- creating or signing an RC1 tag;
- pushing commits, tags, or artifacts;
- real public DNS, public ACME/certificates, public Caddy reachability, an
  external browser/customer path, and a real customer deployment.

No commit, local clean-worker result, HTTP response, or internal Edge process
is represented as proof of those external outcomes.
