# Linux Host Native Overlay: Canonical Service Contract & Backend Scope

## 1. Overview

The Linux Host Native Overlay establishes the canonical systemd unit and backend scope recognition for the host bootstrap service (`acornfox-host-bootstrap.service`).

This contract maintains strict separation between the backend candidate distribution and the host-native overlay:
- `AcornFoxV1RequiredFiles` and all predecessor candidate inventories remain completely unchanged.
- The optional host bootstrap unit is installer-owned and does not enter candidate `want` sets or substrate receipts.
- The same backend candidate remains valid before Linux host provisioning and within Mac virtualization guests.

## 2. Canonical Unit Contract (`internal/hostoverlay`)

The `internal/hostoverlay` package is a dependency-free leaf package that defines the immutable canonical unit constants, byte representation, and filesystem metadata. It has no dependencies on `internal/install`, `internal/desktopupdate`, or `internal/hostprovision`.

### Unit Specification

- **Unit Name**: `acornfox-host-bootstrap.service`
- **Unit Path**: `/etc/systemd/system/acornfox-host-bootstrap.service`
- **Unit Permissions**: Mode `0644` (regular file, root-owned, single hard link `nlink == 1`)
- **Enable Link Path**: `/etc/systemd/system/multi-user.target.wants/acornfox-host-bootstrap.service`
- **Enable Link Target**: `../acornfox-host-bootstrap.service` (symlink, root-owned, single link `nlink == 1`)

### Exact Canonical Bytes

```ini
[Unit]
After=network-online.target docker.service postgresql.service acornfox-upgrade-safe.target
Wants=network-online.target
Requires=acornfox-upgrade-safe.target

[Service]
Type=oneshot
RuntimeDirectory=acornfox-host
RuntimeDirectoryMode=0700
ExecStart=/usr/local/libexec/acornfox-host-bootstrap start
RemainAfterExit=yes
TimeoutStartSec=300

[Install]
WantedBy=multi-user.target
```

Any modification to these directives represents a formal compatibility migration rather than arbitrary unit configuration.

## 3. Host-Scope Recognition (`internal/install`)

The backend host-scope validation (`acornFoxValidateProductionSystemdWithBootLinks`) recognizes this optional external unit alongside the core product units without expanding candidate inventory.

### Accepted Restart-Safe States

1. **None**: Neither the unit file nor the enable symlink exists.
   - Standard state for Mac guests and pre-provisioned Linux systems.
2. **Exact Unit-Only (Staged)**: The exact unit file exists at `/etc/systemd/system/acornfox-host-bootstrap.service` without the enable symlink.
   - Safe interruption boundary during host provisioning before service activation.
3. **Exact Unit + Canonical Enable Link**: The exact unit file exists, and the canonical symlink `/etc/systemd/system/multi-user.target.wants/acornfox-host-bootstrap.service` points to `../acornfox-host-bootstrap.service`.
   - Normal provisioned and activated state.

### Negative Class Rejection

The preflight validation rejects with `ErrAcornFoxLiveConflict` on any drift:
- **Link-Only**: Symlink exists while the unit file is missing or damaged.
- **Content / Digest Mismatch**: Any deviation in unit bytes or SHA-256.
- **Mode Mismatch**: Unit file permissions other than `0644`.
- **Ownership Mismatch**: Unit file or enable symlink not owned by the root role.
- **Link Count Mismatch**: Hard-link count greater than 1.
- **Type Mismatch**: Unit file that is not a regular file (e.g. symlink, directory) or enable link that is not a symlink.
- **Target Mismatch**: Enable symlink pointing anywhere other than `../acornfox-host-bootstrap.service` (e.g. absolute paths or different units).
- **Foreign Conflict**: Any other unexpected `acornfox-*` file or directory in `/etc/systemd/system` (such as `.d` drop-in directories or auxiliary services).

### Bounded Directory Inspection

- Shared OS directory `/etc/systemd/system/multi-user.target.wants` is never scanned or walked; only the exact link pathname is inspected. Unrelated system services in this directory are untouched and preserved.
- Fixed enable link is checked deterministically, even when the unit file is absent or omitted from root enumeration.
