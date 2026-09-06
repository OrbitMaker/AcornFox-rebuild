# AcornFox first-host integration — 2026-09-06

Scope: actual Ubuntu 24.04 amd64 installation and delivery diagnostics on the
single authorized Alibaba test instance. The final public candidate, clean
reinstallation, reboot, upgrade/recovery and public HTTPS acceptance remain open.

## Verified evidence

- The real internal `0.1.0-beta.0` candidate was built in a network namespace
  with no network access, using pinned Go/Node/runtime inputs and populated
  dependency caches. The integrated build took 86.89 seconds and exported the
  installer's exact six-file set.
- Repository bootstrap and all 34 PostgreSQL migrations completed. The installed
  administrator command created the first credential; real HTTP login succeeded.
- A public Git application imported in 1.75 seconds and its real image build was
  accepted in 13.46 seconds. The Agent observed a running container and its
  loopback application returned HTTP 200 with a 439-byte response.
- Separate systemd credential probes proved the Agent could read its own injected
  credential and could not read either root-only key source or the Server's
  injected credential, including with its normal supplementary groups.
- A temporary restricted container resolved public DNS and reached HTTP and
  certificate-validated HTTPS. Host, metadata, private-network, cross-container,
  other-port and IPv6 attempts failed. The corresponding kernel denial counters
  increased; the temporary container was removed. Full root network verification
  also passed after this traffic.
- Actual nftables 1.0.9 JSON roundtrip in a private network namespace passed after
  matching the kernel's chain ordering and ct-state set representation. Rule
  actions/order and ownership verification remain strict.
- Linux runtime-configuration publication/recovery tests passed in 55.843 seconds;
  predecessor-aware six-file export tests passed in 6.086 seconds.

## First-host defects resolved in source

1. Production staging was inadvertently blocked by the task-root path blacklist.
   Only the validated fixed production install directory is now exempt.
2. Shared OS ancestors were treated as product-owned directories. Ubuntu's
   root:syslog 0775 log parent is preserved; product ownership receipts cover only
   product-owned paths.
3. Service caches/logs invalidated static installation recovery. Published
   activations permit untrusted data under exact service roots while checking
   each fixed root and scaffold; initial materialization remains strict.
4. Active/current execution traverses activation directories. Production uses
   0711 traversal-only directories and root-only 0600 metadata, including narrow
   recovery of an empty private creation prefix.
5. Recovery services lacked read traversal of service-owned directories. The
   unchanged sandbox succeeded with only CAP_DAC_READ_SEARCH added.
6. The runtime bridge requires br_netfilter and bridge packet filtering. Two
   fixed kernel preparation commands precede the restricted network helper.
7. First-run configuration, mTLS credentials, console static serving and the
   no-argument health command were absent or incomplete. Configuration now uses
   a private durable intent, atomic directory publication and LoadCredential.
8. The two Caddy processes shared an admin port. Their loopback admin endpoints
   are now distinct, and Caddy uses service-owned persistent home directories.
9. Missing externally prepared runtime networks could fall back to unguarded
   creation. Clean Agent deployments now require the exact prepared topology and
   explicitly set the firewall-permitted public DNS resolvers.

The initial PostgreSQL retry was caused by the earlier test fixture's passwordless
role, not by a successful clean provision. Its two fixture databases were backed
up and removed, and the installer then created its own role/database from its
retained environment.

## Qualification and evidence locations

The live delivery above used session diagnostics for the recovery capability,
activation traversal permissions, kernel prerequisites and Caddy configuration.
A new candidate containing all corrections must be installed without these
session overrides before final host acceptance. Runtime configuration and
upstream native-license/corresponding-source completion are tracked in the same
project leaf ledger; internal beta0 artifacts are not for public distribution.

Raw, secret-free reports are under `.omx/evidence/aliyun-mvp-20260905/`, including
`internal-beta0-integrated-summary.json`, `installed-delivery-response.txt`,
`systemd-credential-separation.txt`, `runtime-container-boundary.txt`,
`runtime-network-after-traffic.txt`, `runtime-nft-roundtrip-fixed.txt`,
`runtime-configuration-linux-tests.txt` and `successor-export-linux-tests.txt`.
Private keys, passwords, sessions and database backups are not included in those
reports or this source repository.
