# Gate 5 RC1 dual-architecture release evidence — artifact PASS

This record accepts the **local release-candidate artifact and reproducibility
boundary** for Open Card `0.8.0-rc.1`. It does not accept a production
deployment, public DNS or ACME, a customer environment, backup and monitoring,
or the live Linux ARM64 upgrade path.

Every published metadata object in this record continues to declare
`production_accepted=false`.

## Source and tag identity

- Source commit:
  `0d5c96bf7b7bd1c641b108cbbd54511d814f2aa0`.
- Version and migration: `0.8.0-rc.1` / `0024`.
- Local annotated tag: `v0.8.0-rc.1`.
- Annotated tag object:
  `b2e21427051c4939d2cdf24d101871c39d249044`.
- Dereferenced tag target:
  `0d5c96bf7b7bd1c641b108cbbd54511d814f2aa0`.
- The tag is intentionally unsigned. No signing key, `tag.gpgSign` policy, GPG
  format, or local GPG secret key was configured. This matches the unsigned
  annotated RC0 precedent and does not claim signature assurance.
- The tag is local only. No commit, tag, or artifact was pushed.

Before tagging, the only invalid local ref was confirmed to be an Apple
`.DS_Store` file under `.git/refs`. That exact non-ref file was moved
recoverably to local Trash. A fresh `git fsck --no-dangling` then exited zero
with no output, and the worktree remained clean.

## Independently rebuilt artifacts

Two distinct clean detached clones, with separate Git directories, rebuilt
both architectures at the exact source commit. The publishable `release/`
trees are byte-identical between clone A and clone B for each architecture.

| Architecture | `release/manifest.json` | Production archive | `bundle-manifest.sha256` |
| --- | --- | --- | --- |
| `amd64` | `1cf02e4a111e38a4061c692de418b67755a2e55f97a04cbc92cee8cb9f82a7be` | `9056cb46537537f6cab21482d900160486098d857955d23b0ca8f131a9cc4233` | `d0e8c111dcaa334c89bb815fc2ddc9b122887cddbbf7c59b6eb51436b931706f` |
| `arm64` | `6bf1e590c3054d373d9319f03581d7a623ee3093b53ddba7b343cf8af7f85fed` | `56a697aed3a8f77261cfeb3074a7d7ab0cfb6389ab5d75225ad9931b665bfa86` | `5fda1e9d0f80deadf6b87cb281d80793c9d1e910386624bc5975cdd0464a2650` |

Each manifest contains 68 payload files. The archive contains the matching
release payload, Web distribution, SBOM, license/source manifests, eight Open
Card binaries, recovery units, and architecture-specific runtime inputs.

The two candidate-root `build-record.json` files are not byte-identical because
they retain the task-local command and temporary output paths used for that
build. They are not part of the publishable release payload. The certifier
normalizes only those execution-local facts and requires the manifest-bound
artifacts, release trees, tool Git blobs, modes, SBOM, source manifest, Web
attestation, and semantic build facts to match. Its declared scope is therefore
honestly `artifact_equality_only`, not whole-directory byte equality.

## Architecture-matched RC0 lineage

RC1 preserves an exact same-architecture RC0/0023 predecessor identity.

| Architecture | RC0 release manifest | RC0 archive | RC0 bundle manifest |
| --- | --- | --- | --- |
| `amd64` | `3b3953c0a26f8706151583ad6c9cad6b5502da18b28f11ed66ca92fe604aa253` | `abc034ed24e8e8dc74b8eabc84dd3071a66f166abe65135502911e9153c0b9fc` | `960ab65526b890009e1770ad190a70b1589f825e0f59cf8d757634a0a8848392` |
| `arm64` | `e4f56105b3d184313d51365c7fff40b9f68111815def83c5e5985bc182177a57` | `9560df1d4a739c729d857cd93b989b99976da0e86983ffa026d13202339d57b9` | `fdfd6b6108870118714b70c9007937585fc0429d14fa9d64010a80016edc2a15` |

Both lineages use source commit
`35a2b198ac52949af3477475d89d4813b46a9490`, version `0.8.0-rc.0`, and
migration `0023`. ARM64 runtime upgrade acceptance remains fail-closed until a
real Linux ARM64 environment executes the atomic upgrade path.

## Certification and security evidence

| Evidence | SHA-256 |
| --- | --- |
| `certification.json` | `22b41c0221f0c159520209dc385557f1918e7205c6b71b2dd1fa9564ac55bc87` |
| `release-index.json` | `784199b3faceb3f757a5b1dbdc1b1ee55a02ab84131a6ea86724a76d965a54a6` |
| `security-scan.json` | `b675e2c7e46b4000e789025bf7a20d32bc0c9be05ab4f17f0721d720940ee3a1` |

The certification and release index contain no task-local absolute paths or
secrets. The index binds the certification digest, both architecture triples,
the exact RC0 lineage, the source commit, version, and migration.

The security scan used:

- explicit Go `1.25.13` with binary SHA-256
  `f088799ea6fa0e837755306c027d75345e761b3cd1b2a7db45c41ec14bd6500f`;
- pinned `govulncheck v1.7.0` with binary SHA-256
  `c900316beb80c6fb031cc13a737031fd9a3ab0ca5e9477ed656ce107d543c65b`;
- the official `https://vuln.go.dev` database, last modified
  `2026-08-28T14:47:45Z` at scan time;
- 181 parsed JSON protocol documents, zero vulnerability findings;
- source, candidate, archive, and certification secret scans with zero blocking
  findings and 17 explicitly identified test-fixture canaries.

## Clean-clone gates

The two clean clones ran the release gates sequentially so task-scoped
PostgreSQL resources could not collide. Both gate manifests were independently
verified with SHA-256:

- clone A gate manifest:
  `c821881e85b2cb23a5bfba0baaad28ab0776ca9296599788c0c147b60f783bff`;
- clone B gate manifest:
  `33990129d14e04270dd15e90c2985eba7686f9adc20979b4e73fede9dc2012ea`.

Each clone passed:

- `go test -count=1 ./...`;
- `go test -race -count=1 ./...`;
- `go vet ./...`;
- `npm ci` with zero reported vulnerabilities;
- Web lint, typecheck, 24 files / 159 tests, production build-contract, and
  production build;
- 54 G2/G5 Python release tests;
- all MVP shell syntax checks and `git diff --check`.

No test skip is represented as a pass.

## ARM64 structural installation boundary

On the ARM64 development host, the installer rejected the AMD64 candidate
before staging with `release architecture amd64 is incompatible with runtime
arm64`. The ARM64 candidate then passed a task-root-only dry-run,
non-activating structural install, and idempotent replay. The staged `current`
pointer, release source/manifest, binaries, Web payload, runtime inputs, and
upgrade units were inspected under that task root.

This did not execute Linux ARM64 binaries, systemd, Caddy, PostgreSQL, the
atomic upgrade engine, or any production path. The exact task roots and logs
were moved recoverably to local Trash after verification.

## Acceptance boundary

Accepted:

- reproducible AMD64 and ARM64 RC1 release artifacts;
- exact RC0/0023 same-architecture lineage;
- clean-clone source, unit, Web, Python, vulnerability, and secret gates;
- local unsigned annotated tag bound to the recorded evidence;
- ARM64 structural install and wrong-architecture rejection.

Still pending and not implied by this tag:

- live Linux ARM64 runtime or atomic upgrade acceptance;
- Tencent staging selection, deployment, firewall, or DNS changes;
- real systemd/Caddy/PostgreSQL staging activation and reboot recovery;
- public DNS, ACME staging or production certificates;
- backup timers, encrypted off-host storage, monitoring, and alert delivery;
- external browser, customer, production cutover, or 24-hour acceptance.
