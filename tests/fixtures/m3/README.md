# Open Card M3 isolated routing fixtures

This directory is a deterministic, data-only fixture set for M3.  It is
intended to exercise the RouteProvider/Caddy, domain, DNS-01, certificate,
fallback, and safe-cutover contracts without contacting public DNS, a public
ACME endpoint, or a production certificate authority.

## Isolation contract

All names end in `.test`, and all DNS traffic is addressed to the loopback
fixture listener (`127.0.0.1:15353`).  The fixture's A records resolve only to
`127.0.0.1`; the CNAME target is also inside the fixture zone.  The Caddy
admin listener is valid only on `127.0.0.1:2019`.  The non-loopback admin
sample is a rejection vector and is never an instruction to bind a real
service.

No private key, credential, access token, DNS-provider secret, or ACME account
material is stored here.  Certificate files contain metadata and stable
fingerprints only.  `private_key_ref` and `secret_provider` values are opaque
references that the test harness must resolve through its in-memory
SecretProvider; they are not secret material.

## Fixture index

| Path | Contract covered |
| --- | --- |
| `dns/zone.json` | Loopback zone, platform A record, wildcard A record, and DNS-01 TXT record. |
| `dns/provider.json` | Credential-free loopback DNS provider operations. |
| `dns/cname-valid.json` | Valid custom-host CNAME and resolver result. |
| `dns/cname-pending.json` | CNAME present but not yet visible; route must remain disabled. |
| `dns/cname-invalid.json` | Wrong CNAME target; IP fallback remains available. |
| `certs/platform-wildcard.json` | Internal CA metadata for the platform wildcard certificate. |
| `certs/ca-metadata.json` | Fixture-only CA metadata; no private key material. |
| `certs/app-renewal.json` | Deterministic application certificate issuance and renewal metadata. |
| `certs/acme-dns01-failure.json` | DNS-01/ACME failure; application must not be rebuilt. |
| `backends/frontend.json`, `backends/api.json` | Stable HTTP responses for the only externally routable services. |
| `caddy/routes-valid.json` | Atomic, host + path-prefix route generation for frontend and API. |
| `caddy/route-provider-contract.json` | Apply/observe/remove/rebuild/idempotency contract. |
| `caddy/routes-invalid-overlap.json` | Overlapping path prefixes that must be rejected. |
| `caddy/routes-invalid-worker-db.json` | Worker/database exposure that must be rejected. |
| `caddy/routes-invalid-admin.json` | Public Caddy admin address that must be rejected. |
| `caddy/restart-rebuild.json` | Crash/restart and deterministic rebuild from Open Card route facts. |
| `domain/platform-binding.json` | Verified platform domain and stable application slug. |
| `domain/unverified-fallback.json` | First-install IP + system-port fallback before domain verification. |
| `domain/conflicts.json` | Host/path and domain binding conflict expectations. |
| `switch/success.json` | Healthy-new-version, atomic switch, observation, old-version close timeline. |
| `switch/failure-health.json` | New-version health failure; old version and fallback remain serving. |
| `switch/failure-certificate.json` | Certificate failure affects domain route only; application remains intact. |
| `security/admin-non-loopback.json` | Explicit fail-closed assertion for non-loopback admin binding. |
| `state/status-matrix.json` | User-visible state vocabulary without fabricated percentages. |
| `observability/audit-secret-redaction.json` | SSE/audit replay with certificate key material redacted. |
| `manifest.sha256` | Hash of every checked-in M3 fixture except the manifest itself. |

Consumers should treat Open Card facts as authoritative.  The Caddy JSON is a
derived artifact: deleting it and rebuilding it from the route facts must
produce the same canonical route set and generation hash.  Every mutating
scenario is safe to replay with the same idempotency key.
