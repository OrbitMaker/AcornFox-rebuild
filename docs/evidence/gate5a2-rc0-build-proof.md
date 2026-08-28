# Gate5A-2 RC0 amd64 build proof

This record contains only reproducibility and task-safe installation evidence.
The candidate payload remains an ignored local artifact and is not in Git.

## Fixed provenance

- Candidate: `0.8.0-rc.0`, migration `0023`, architecture `amd64`.
- Application source commit: `58a347536fab29515622432651dff48849f3e251`.
- Build driver and bundle tool commit: `37f48825eedd3f758de90abd546529da44c94085`.
- Runtime-input manifest SHA-256: `e06b81640a1225029ec0f548a22a05bb0d9957a8207f3347830a14c80973ef8a`.
- Driver SHA-256: `6f899d0996e369ad7248c4eeceac5740ffc5508a1c3e09c44bdc1626d32e712d`.
- Bundle-tool SHA-256: `8d3d0e888a3d80c11f28af8381a48fa23a10e3ec0eda9b5a0f91a91570df4ed0`.

The build record confirms `GOOS=linux`, `GOARCH=amd64`, `CGO_ENABLED=0`,
`GOWORK=off`, Go `1.25.13`, Live same-origin metadata, and
`production_accepted=false`.

## Two independent builds

The primary ignored candidate was built at
`output/production/0.8.0-rc.0/amd64`. A second independently cached build was
produced in a task-specific `/tmp` directory, compared, then moved to the
local Trash as recoverable cleanup. Both builds produced exactly these SHA-256
values:

| Artifact | SHA-256 |
| --- | --- |
| `open-card-0.8.0-rc.0-production.tar.gz` | `4dfbf6e86eb58c317e190edf3749bc56ac964d46a751b30c7a9fb330091c39ac` |
| `release/manifest.json` | `608fefe6c73999d2e552476f7a32bfc70dd339ab502a6f7b08cc2f75c6069ab4` |
| `bundle-manifest.sha256` | `c8df4a67e69afe259ab2747434058528dd7d2556a56eae554f73ca19c35b6a91` |

Independent release validation confirmed all 62 manifest payload paths, modes,
and digests exactly matched the on-disk release; no symlink, fixture, or test
payload was accepted.

## Task-safe install smoke

The following local-only, non-activating dry run used a task-specific `/tmp`
root, the local release directory, `--offline`, and the exact manifest hash:

```text
bash scripts/mvp/install.sh --root /tmp/open-card-g7-g5a2.<task> \
  --bundle output/production/0.8.0-rc.0/amd64/release --offline --dry-run \
  --expected-manifest-sha256 608fefe6c73999d2e552476f7a32bfc70dd339ab502a6f7b08cc2f75c6069ab4
```

It returned status `1` with `manifest fields are invalid`. This is the known
Gate5B compatibility blocker: the current installer accepts the historical
RC1 manifest lineage and rejects the RC0 manifest's `source_commit` field.
No system root, service activation, Caddy, PostgreSQL, cloud, or server action
was attempted.

## Cleanup

- The temporary 58a detached source worktree was removed with `git worktree
  remove`, then `git worktree prune` was run.
- The second build output was moved to local Trash; only the ignored primary
  candidate remains under `output/production/0.8.0-rc.0/amd64`.
