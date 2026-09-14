# AcornFox Linux Host Provisioning (LI-2)

## 1. Overview

The Linux host provisioner (`internal/hostprovision` and `cmd/acornfox-host-provision`) is an installer-only root module designed to install and pin the stable host bootstrap executable, external C0 launcher and controller binaries, durable slot/controller state roots, and precreated slot lock, and publish the canonical `host-runtime.json` trust input on native Linux hosts.

This module executes after candidate package unpacking and backend readiness confirmation, but before starting `acornfox-host-bootstrap.service`. It guarantees that all initial execution baselines are cryptographically verified, anchored to root-owned single-link regular files, and validated against both the live guest instance identity and fresh backend observation before `host-runtime.json` is published.

---

## 2. Fixed Target Layout & Permissions

The provisioner targets the exact paths defined by the immutable host configuration contract (`internal/hostconfig`):

| Target Path | Perm | Owner | Description |
| :--- | :--- | :--- | :--- |
| `/usr/local/libexec/acornfox-host-bootstrap` | `0755` | `root:root` | Stable host bootstrap executable (single-link regular ELF) |
| `/usr/local/lib/acornfox-host/bootstrap` | `0755` | `root:root` | Bootstrap root directory for external C0 tree |
| `/usr/local/lib/acornfox-host/bootstrap/launcher` | `0755` | `root:root` | Launcher directory |
| `/usr/local/lib/acornfox-host/bootstrap/launcher/acornfox-host-launcher` | `0755` | `root:root` | External C0 launcher binary (distinct inode) |
| `/usr/local/lib/acornfox-host/bootstrap/controller` | `0755` | `root:root` | Controller directory |
| `/usr/local/lib/acornfox-host/bootstrap/controller/acornfox-host-update` | `0755` | `root:root` | External C0 controller binary (distinct inode) |
| `/var/lib/acornfox-host/slots` | `0700` | `root:root` | Durable HostSlots state root |
| `/var/lib/acornfox-host/slots/lock` | `0600` | `root:root` | Precreated slot mutex lockfile |
| `/var/lib/acornfox-host/controller` | `0700` | `root:root` | Durable HostController state root |
| `/etc/systemd/system/acornfox-host-bootstrap.service` | `0644` | `root:root` | Canonical systemd service unit (published **before** config) |
| `/etc/systemd/system/multi-user.target.wants/acornfox-host-bootstrap.service` | `symlink` | `root:root` | Canonical enable symlink (published **after** config) |
| `/etc/acornfox-host/host-runtime.json` | `0600` | `root:root` | Immutable host runtime configuration |

Runtime directory `/run/acornfox-host` is owned by systemd's `RuntimeDirectory` in `acornfox-host-bootstrap.service` (`RemainAfterExit=yes`), not by this provisioner. State ledgers (`state.json` and `ledger.json`) are never initialized by this provisioner; they are owned and initialized by real `HostSlots` and `HostController.Status`.

---

## 3. Core Invariants

1. **Root-Only Access Control**:
   The provisioner strictly requires effective UID 0 (`os.Geteuid() == 0`). Non-root invocations fail closed immediately with `ErrPrivilegeRequired`.
2. **Immutable Input Contract**:
   CLI options accept only installer source paths, expected SHA-256 hashes, semver version, and verified backend binding hash. No runtime overrides for target root, state root, IndexURL, keys, instance, slot, or executable path are accepted.
3. **Source Verification & Pinning**:
   Source files (`StableBootstrapSource`, `ManagedC0Source`, `PolicySourcePath`) are verified via pinned ancestor directory chains (`O_NOFOLLOW`). Regular files with single link (`st.Nlink == 1`), root ownership, non-writable by other users, and matching SHA-256 digests are required. ELF binaries must be valid 64-bit little-endian executables or PIE with non-zero entry points matching host architecture (`amd64` / `arm64`).
4. **Guest Instance Identity Binding**:
   Instance identity is read from the fixed `/etc/acornfox-host/guest-instance.json` (kind `linux-local`). The bootstrap host version in the descriptor must match the requested bootstrap version.
5. **Fresh Backend Observation Gate**:
   Before publishing `host-runtime.json`, the provisioner invokes `Observe(ctx, "")` via `NewGuestBackend` using `NewPrivilegedLocalGuestTransport`. It strictly requires:
   - `obs.LocalLoopback == true`
   - `obs.MigrationVersion == "0040"`
   - `obs.InstanceID == guestInstance.InstanceID`
   - `obs.Architecture == runtime.GOARCH`
   - `obs.Binding == req.BootstrapBackendBinding`
   - `obs.Ready == true`
   - `obs.Finalized == true`
   Any mismatch or failure blocks publication and leaves existing state untouched.
6. **Distinct C0 Binaries & No-Clobber Installation**:
   Launcher (`acornfox-host-launcher`) and controller (`acornfox-host-update`) are installed at separate paths with distinct inodes (`st.Ino`). Hardlinks between them are rejected (`checkDistinctInodes`). Files are published atomically via temporary file creation, `f.Sync()`, and `os.Link` (failing closed if target exists).
7. **Canonical Unit, Policy, and Enable Link Publication Order**:
   - The canonical service unit (`/etc/systemd/system/acornfox-host-bootstrap.service`) is published **before** `host-runtime.json` with mode `0644` and root ownership.
   - The host policy source (`PolicySourcePath`) must be strictly canonical JSON matching `hostconfig.ConfigPolicyFile` without non-standard whitespace or reordered keys; `ExpectedPolicySHA256` and the receipt `PolicySHA256` refer to these exact canonical bytes without reentry hash drift.
   - `host-runtime.json` is published after the unit and binaries are verified.
   - The canonical enable symlink (`/etc/systemd/system/multi-user.target.wants/acornfox-host-bootstrap.service` -> `../acornfox-host-bootstrap.service`) is published **after** `host-runtime.json`.
8. **Dual Production Verification**:
   Immediately following publication (or upon re-entry), the config and tree are validated using production `hostconfig.ReadAndValidateConfigFile` and `desktopupdate.PinHostBootstrap`.
9. **Pre-Mutation Classification & Re-entry State Preservation**:
   - The provisioner classifies existing state before any directory creation or lockfile mutation.
   - When `host-runtime.json` already exists (configured re-entry), all dependencies (`slots`, `slots/lock`, `controller`, `bootstrap`, `launcher`, `controller`, `unit`) must pre-exist with exact modes and root ownership. Missing dependencies fail closed without repairing state. Lock is opened without `O_CREATE`. Pre-existing durable state (`state.json`, `ledger.json`, active slots) is preserved and never reset, clobbered, or adopted. If the enable link is missing, reentry completes only the canonical link (valid resume). If the link exists but is mismatched, it fails closed without clobber.
   - When `host-runtime.json` is absent (fresh or resume), controller root must be empty (preventing adoption of unmanaged or torn state) and slots root may contain at most `lock`. The canonical unit may pre-exist in a staged unit-only state (valid resume); any mismatched unit or existing enable link before config causes immediate failure before creating slots or locks.
10. **Secret-Free Bounded Receipts & Error Desensitization**:
    Receipts contain only instance ID, bootstrap ID, version, binding hash, and artifact SHA-256 digests. Errors never expose raw child stderr, private keys, or internal tokens. Positional or trailing CLI arguments are strictly rejected.

---

## 4. Usage

### Command-Line Interface (CLI)

```bash
acornfox-host-provision \
  -bootstrap-version 1.0.0 \
  -binding-sha 2404b9016e3c... \
  -bootstrap-source /staging/bin/acornfox-host-bootstrap \
  -bootstrap-sha c0de89... \
  -c0-source /staging/bin/acornfox-host-update \
  -c0-sha a1b2c3... \
  -policy-source /staging/config/host-update-policy.json \
  -policy-sha d4e5f6...
```

### Output Receipt (JSON)

```json
{
  "instance_id": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
  "bootstrap_id": "0856f20a656a80fa...",
  "bootstrap_version": "1.0.0",
  "bootstrap_backend_binding": "2404b9016e3c...",
  "stable_bootstrap_sha256": "c0de89...",
  "launcher_sha256": "a1b2c3...",
  "controller_sha256": "a1b2c3...",
  "config_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "policy_sha256": "d4e5f6..."
}
```

### Programmatic Go API

```go
import "github.com/open-card/open-card/internal/hostprovision"

req := hostprovision.ProvisionRequest{
    BootstrapVersion:        "1.0.0",
    BootstrapBackendBinding: bindingSHA,
    StableBootstrapSource:   "/staging/bin/acornfox-host-bootstrap",
    ExpectedBootstrapSHA256: bootstrapSHA,
    ManagedC0Source:         "/staging/bin/acornfox-host-update",
    ExpectedC0SHA256:        c0SHA,
    PolicySourcePath:        "/staging/config/host-update-policy.json",
    ExpectedPolicySHA256:    policySHA,
}

receipt, err := hostprovision.Provision(ctx, req)
if err != nil {
    // Handle error (fail-closed)
}
```
