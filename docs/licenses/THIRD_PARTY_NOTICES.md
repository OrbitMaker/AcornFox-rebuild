# Third-party notices

This file is intentionally conservative. It records provenance boundaries for
the offline RC bundle without reprinting upstream license text.

| Component class | Source of terms | Bundle evidence |
| --- | --- | --- |
| Open Card source and Go modules | repository files and `go.mod`/`go.sum` | source manifest + SBOM |
| Frontend runtime | `web/package-lock.json` and built `web/dist` | source manifest + SBOM |
| Debian packages | caller-supplied `packages.txt` and `debs.sha256` | verified input manifest |
| Caddy, BuildKit, rootlesskit, Buildx | caller-supplied fixed asset manifest | per-architecture asset checksums |

The bundle contains no production Caddy fixture binary. Any fixture or
integration test executable is stored under a test-only archive and is not
listed in a production release manifest.

When a dependency does not ship an accessible notice in the fixed input, the
M7 evidence records `NOASSERTION`; the assembler does not silently claim a
license.
