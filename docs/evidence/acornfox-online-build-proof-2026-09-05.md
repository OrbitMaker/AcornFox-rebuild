# GPT-6 direct takeover: controlled build proof

Date: 2026-09-05. Implementation owner: GPT-6 Astra task
`01a07093-782b-7622-bab8-a62d187e1dbe`. Reviewed implementation commit:
`26fc9a1b68d5dfb21105b86a41de6a526f86898a`.

## Result and scope

`AFB-BUILD-03B-PRODUCT` P2–P5 completed as a **task-worker build proof**.
It does not accept a release candidate, an installed control plane, production
worker-attestor composition, a public HTTPS application or a public release.
The normal Server/delivery composition still defaults to offline mode. Its real
worker attestor and controlled binding remain mandatory before 12B/host acceptance.

The former Sol execution owner explicitly stopped all writers and tests before
handoff at `426d1079`. GPT-6 performed the changes and remote execution directly;
a separate GPT-6 reviewer returned APPROVE after the evidence defects were fixed.
No former execution chain was resumed.

## Verified outcomes

| Boundary | Result | Evidence |
| --- | --- | --- |
| P2 controlled network | 13/13 probes and all corresponding kernel-counter classes PASS | `afb-build-03b-product-p2/final-gpt6-proof/p2-result.json` |
| P3 real self-build | Two independent roots/caches; each 10 Go binaries + 5 Web files, all bytes equal | `afb-build-03b-product-p3/two-root-proof/result.json` |
| P3 execution | 28 commands, every exit 0; sum of individual command wall times 402.567 seconds | `two-root-proof/*.log.json` |
| P3 toolchain | 19,570 installed files matched pinned archives; original execution/audit driver identities recorded separately | `two-root-proof/toolchain-provenance.json` |
| P4 real provider | rootless BuildKit 0.32.2 downloaded exact dependency bytes into OCI; metadata access and kernel-policy drift rejected; 9.58 seconds, no SKIP | `afb-build-03b-product-p2/final-provider-proof/provider-e2e.txt` |
| P4 limits | 512 MiB / 50% CPU / 4 GiB state, max-parallelism=1, independent non-sudo account, process sandbox | worker unit/config, cgroup and namespace evidence |
| Source identity | Rebuilding the Linux integration test after commit produced the identical executable that passed on the VM | `final-source-binding.json` |
| P5 cleanup | Exact VM, disk/seed and task directories removed; seven other VMs, host firewall/default route/AppArmor unchanged | `reclaim-receipt.json` |

Raw paths in the table are relative to `.omx/evidence/`. Per-directory
`manifest.sha256` files bind the copied evidence. The Alibaba installation
instance was not used or modified by these worker tests.

## What was fixed

1. The old Python probe encoded DNS binary escapes and HTTP CRLF as literal
   backslashes. The DNS transaction ID was eight bytes instead of two. The
   corrected probe has wire-format regression coverage, including fragmented
   TCP responses and truncated-frame rejection.
2. Probes no longer pass merely because connection attempts throw exceptions.
   Final acceptance requires all expected rows and increases in matching nft
   allow/deny counters, including IPv6, unexpected DNS and private/CGNAT ranges.
3. The proof runs as a guest-local service, persists its result and then removes
   only the task firewall table. It no longer depends on keeping a new SSH
   connection open while strict ingress denial is active.
4. The default Go module endpoint was unreachable directly in this environment.
   The fixed policy now explicitly records the reachable Go mirror and signed
   China checksum endpoint. Dependency versions, integrity hashes and network
   denial were retained. Official checksum semantics:
   <https://golang.google.cn/ref/mod#authenticating>.
5. The self-build driver rejects optimized Python and records failed timeout
   receipts while killing the owned command group. Toolchain bytes and proof
   input identities are recorded. The successful original driver is preserved
   separately, with its reconstruction explicitly labeled and checked against
   the SHA-256 recorded inside the guest; newer driver bytes are not relabeled
   as the successful execution's source.
6. The policy-drift negative uses a fresh context and an explicit attestor
   mismatch counter, preventing an unrelated timeout from satisfying the test.
7. The final single-concurrency worker configuration is readable by its isolated
   account under a root-owned task directory. The first permission-denied
   attempt is retained; `/etc/acornfox` permissions were not weakened.

## Local checks and remaining release work

Seven Python regressions, focused input-policy tests, full BuildKit package
normal/race tests, Go vet, Python compilation, shell syntax, formatting and diff
checks passed. The Linux integration test was actually run, not only compiled.
The two-root proof used source `15f3fb979876b6e6ac03b8c6bf68ed9638e4401e` as
explicitly frozen in P0; its artifacts must not be called a candidate built from
the later implementation commit.

Next remains `AFB-RELEASE-12B-BOOTSTRAP` / `12B-SUCCESSOR`: close real release
inputs and production composition, assemble the actual candidate pair, then
run clean-host, external HTTPS and publication gates. No extra functional scope,
customer/invitation requirement, cloud instance or monitoring loop was added.
