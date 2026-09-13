# AcornFox Guest Update Worker Provisioning

## 1. Overview

The guest update worker provisioning component (`internal/desktopupdateguest/provision_linux.go` and `cmd/acornfox-guest-provision`) is an installer-only root module designed to publish and anchor the privileged guest update worker, native instance identity, state directory, and verification policy on native Linux and macOS guest environments.

This provisioning logic belongs to the native outer installer and initial seed bootstrap, rather than the inner backend payload bundle. It establishes the trusted execution baseline required by `desktopupdateguest.Open()`.

---

## 2. Fixed Target Layout & Permissions

The provisioner targets the exact paths defined in `internal/desktopupdateguest/executor_linux.go`:

| Target Path | Perm | Owner | Description |
| :--- | :--- | :--- | :--- |
| `/usr/local/libexec/acornfox-guest-update` | `0755` | `root:root` | Privileged guest update executable |
| `/etc/acornfox-host/guest-instance.json` | `0600` | `root:root` | Instance identity descriptor |
| `/etc/acornfox-host/linux-owner-marker` | `0600` | `root:root` | Linux native owner marker (created once, 64-hex ID) |
| `/var/lib/acornfox-desktop/owner-marker` | `0600` | `root:root` | macOS guest native owner marker (read-only, preserved) |
| `/var/lib/acornfox-host/guest-update` | `0700` | `root:root` | Private guest update state directory |
| `/etc/acornfox-host/guest-update-policy.json` | `0600` | `root:root` | Update policy (published **last**) |

---

## 3. Core Invariants

1. **Root-Only Access Control**: The provisioner fails closed (`ErrPrivilegeRequired`) immediately if the caller's effective UID is non-zero.
2. **Strict Identity Derivation**:
   - `mac-managed`: Preserves existing `/var/lib/acornfox-desktop/owner-marker`; `InstanceID = sha256("mac-managed:" + NativeUUID)`.
   - `linux-local`: If `/etc/acornfox-host/linux-owner-marker` exists, it is validated and preserved. If absent, it is generated once using 32 crypto-random bytes (64-character lowercase hex); `InstanceID = sha256("linux-local:" + NativeID)`.
3. **Policy Published Last**: All directories, the worker executable, marker, instance descriptor, and state directory are validated and persisted before writing `guest-update-policy.json`. If provisioning is interrupted, `desktopupdateguest.Open()` safely returns `ErrNotConfigured`.
4. **Idempotency & Mismatch Protection**: Re-invoking the provisioner with identical inputs succeeds without modifying or resetting state. Any existing mismatched file, symlink, or unexpected foreign file causes `ErrConflict` without modifying existing files.
5. **No Runtime Overrides**: The public API (`Provision`) accepts no destination root overrides or shell fragments; tests use a package-private anchor parameter.

---

## 4. Usage

### Programmatic Go API
```go
import "github.com/open-card/open-card/internal/desktopupdateguest"

req := desktopupdateguest.ProvisionRequest{
    Kind:                 "linux-local", // or "mac-managed"
    BootstrapHostVersion: "1.0.0",
    WorkerSourcePath:     "/staging/acornfox-guest-update",
    ExpectedWorkerSHA256: "<64-character-hex-sha256>",
    PolicySourcePath:     "/staging/guest-update-policy.json",
    ExpectedPolicySHA256: "<64-character-hex-sha256>",
}

receipt, err := desktopupdateguest.Provision(ctx, req)
if err != nil {
    // Handle error
}
// receipt contains verified InstanceID, NativeID, and artifact hashes
```

### Installer CLI
```bash
acornfox-guest-provision \
  -kind linux-local \
  -bootstrap-version 1.0.0 \
  -worker-source /path/to/worker \
  -worker-sha <sha256> \
  -policy-source /path/to/policy.json \
  -policy-sha <sha256>
```
Output: JSON-encoded `ProvisionReceipt` containing verified public digests and instance metadata.
