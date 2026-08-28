# Gate5A-3 installable RC0 amd64 build proof

This record contains provenance, reproducibility, and task-safe installation
evidence only. Both candidate payload directories remain ignored local
artifacts and are not committed to Git.

## Source and tool provenance

- Installable RC0 source branch: `codex/open-card-rc0-baseline`.
- Installable source commit: `35a2b198ac52949af3477475d89d4813b46a9490`.
- Source parent: `58a347536fab29515622432651dff48849f3e251`.
- Build tool commit: `4576963560bf7c052e6a0f1bce39a4f8b6666d92`.
- Runtime-input manifest SHA-256: `e06b81640a1225029ec0f548a22a05bb0d9957a8207f3347830a14c80973ef8a`.
- Driver SHA-256: `865ac80e9413eab684ea875e99d5bd22a9c765001eca3afea55608dcd8126884`.
- Bundle-tool SHA-256: `19579052e69859189518d7ee6b10ee5edcde797905a4783b4fd733e6d8932c96`.

The candidate build record confirms Go `1.25.13`, `GOOS=linux`,
`GOARCH=amd64`, `CGO_ENABLED=0`, `GOWORK=off`, four checksum-pinned runtime
inputs, seven Open Card binaries, and a Live same-origin Web attestation.
It continues to declare `production_accepted=false`.

## Primary and historical candidates

- Installable primary candidate:
  `output/production/0.8.0-rc.0/amd64`.
- Preserved historical non-installable `58a` candidate:
  `output/production/0.8.0-rc.0/amd64-58a-noninstallable`.

The installable primary candidate source commit is `35a2b19…`; it must not be
confused with the preserved `58a` archive.

## Two independently cached builds

The primary candidate and a second task-specific `/tmp` build, each with fresh
private Go and npm caches, produced exactly these SHA-256 values:

| Artifact | SHA-256 |
| --- | --- |
| `open-card-0.8.0-rc.0-production.tar.gz` | `abc034ed24e8e8dc74b8eabc84dd3071a66f166abe65135502911e9153c0b9fc` |
| `release/manifest.json` | `3b3953c0a26f8706151583ad6c9cad6b5502da18b28f11ed66ca92fe604aa253` |
| `bundle-manifest.sha256` | `960ab65526b890009e1770ad190a70b1589f825e0f59cf8d757634a0a8848392` |

Independent validation confirmed all 62 manifest payload entries exactly
matched path, SHA-256, and mode. `release/`, `release/web/`, and
`release/web/dist/` are `0755`; `web/dist/index.html` is `0644`.

## Task-safe installation

The native ARM64 host first rejected the amd64 candidate before staging, as
expected. Structural installation was then tested only beneath a task-specific
`/private/tmp/open-card-g7-g5a3.*` root with a local `uname -m` shim returning
`x86_64`; the shim did not run candidate binaries or affect the host.

With `--offline`, an exact manifest SHA, no `--activate`, and explicit
`--test-safe-prefix /private/tmp`, all three actions passed:

1. dry-run;
2. non-activating install; and
3. idempotent replay.

The resulting `current` pointer targets `releases/release-0.8.0-rc.0`, the
installed `source-commit.txt` equals `35a2b19…`, five unit files were copied
only under the task root, and no host service, listener, process, Caddy,
PostgreSQL, cloud, or server mutation was performed.

## Cleanup completed

- The task-specific install root and second `/tmp` output were moved to local
  Trash rather than destructively removed.
- The task-specific detached build-source and side-source worktrees were
  removed with `git worktree remove`, followed by `git worktree prune`.
- The `codex/open-card-rc0-baseline` branch remains at `35a2b19…`.
- Both ignored candidate directories remain: installable `amd64` and historical
  `amd64-58a-noninstallable`.
