# Linux Host Lifecycle Architecture: Bootstrap, Admission IPC, and Managed Controller Composition

## 1. Overview and Process Model

In the AcornFox Linux host architecture, host updates do not rely on a persistent daemon, resident broker, SCM_RIGHTS descriptor passing, or secondary persistent update ledgers. Instead, invocation is strictly **oneshot** and **fail-closed**, driven on-demand by systemd units (such as oneshot timers or service startup) or root administrators.

```text
root caller (systemd / CLI)
  │
  ▼
acornfox-host-bootstrap <verb>
  │ (flock /run/acornfox-host/invocation.lock with full ancestor verification and revalidation)
  │ (reads /etc/acornfox-host/host-runtime.json via internal/hostconfig)
  │ (PinHostBootstrap verifies static external root)
  │
  ├──► OpenActiveControllerReadOnly
  │      │ (acquires non-blocking slot root lock)
  │      │ (inspects slot ledger & verified binaries)
  │      ▼
  │    callback:
  │      - opens anonymous Unix SOCK_STREAM socketpair with SOCK_CLOEXEC
  │      - launches child via /proc/self/fd/3 with args ["acornfox-host-update", "managed-child"]
  │      - ExtraFiles[0]=controllerFD, ExtraFiles[1]=childSock
  │      - parent immediately closes childSock
  │      - child sends bounded hello-v1 frame BEFORE touching any core roots
  │      - parent receives hello-v1 with deadline
  │      - callback returns (slot root unlocked immediately, no deadlock!)
  │
  ├──► Bootstrap sends admit-v1 over lifecycle socket (carries 32-byte crypto nonce, target slot, role, operation)
  │
  ▼
acornfox-host-update (managed controller child)
  │ (validates admission against static config via internal/hostconfig)
  │ (constructs HostSlots with Linux lifecycle hooks using WithLauncherFD)
  │ (constructs GuestBackend with local guest transport)
  │ (constructs HostController with durable controller root)
  │ (confirms active slot matches target; handles recovery reselect with nonce echo)
  │ (executes verb: status | check | advance | resume-backend | dismiss | start)
  │ (sends bounded desensitized result-v1 frame echoing exact admission nonce)
  │
  ▼
acornfox-host-bootstrap
  │ (validates result nonce and operation)
  │ (reaps child process group; ensures no zombies or orphaned descendants)
  │ (releases invocation lock)
  ▼
exit 0 with JSON receipt on stdout
```

---

## 2. Fixed Filesystem Layout

All production paths are compiled constants. No command-line flag or environment variable may override them:

| Path | Purpose | Permissions / Ownership | Mutability |
| :--- | :--- | :--- | :--- |
| `/usr/local/libexec/acornfox-host-bootstrap` | Immutable bootstrap binary | `0755 root:root` | Read-only |
| `/etc/acornfox-host/host-runtime.json` | Static root-of-trust configuration | `0600 root:root`, 1 link | Read-only |
| `/usr/local/lib/acornfox-host/bootstrap/` | External bootstrap slot tree (C0) | `0700 root:root` | Read-only |
| `/var/lib/acornfox-host/slots/` | Managed slot trees and slot ledger | `0700 root:root` | Managed by HostSlots |
| `/var/lib/acornfox-host/controller/` | Durable controller state & stages | `0700 root:root` | Managed by HostController |
| `/run/acornfox-host/invocation.lock` | Mutual exclusion lockfile | `0600 root:root` | Transient runtime flock |

---

## 3. Protocol v1 Specification (`internal/hostlifecycle`)

Communication between the bootstrap parent and controller child uses **Protocol v1** over an anonymous Unix `SOCK_STREAM` socketpair:
- **Framing**: 4-byte big-endian payload length followed by canonical JSON. Write-full loop guarantees complete delivery across stream fragmentation.
- **Size Bounds**: Total payload size $\le 4096$ bytes. Frames $> 4096$ bytes fail closed immediately (`ErrFrameTooLarge`).
- **Closed Frame Vocabulary**: Only four frames exist: `hello`, `admit`, `reselect`, `result`.
- **Nonce Binding**: Every admission issues a 32-byte crypto random nonce. Both `reselect` and `result` MUST echo this exact nonce.
- **Closed State and Reason Sets**: `State` and `ReasonCode` are strictly validated against closed enumerations.
- **Canonical Equality**: Frames are checked against `bytes.Equal(bytes.TrimSpace(data), canonicalJSON)`. Out-of-order keys, case conflicts, and duplicates fail closed.
- **Information Boundary**: Frames never transmit filesystem paths, cryptographic secrets, URLs, backend bindings, basis leases, or raw error strings.

### Frame Schemas

#### 1. `hello` (Child $\to$ Parent)
```json
{
  "type": "hello",
  "schema_version": 1
}
```

#### 2. `admit` (Parent $\to$ Child)
```json
{
  "type": "admit",
  "schema_version": 1,
  "operation": "advance",
  "role": "normal",
  "slot_id": "8f3b...",
  "instance_id": "4a1c...",
  "nonce": "e92a..."
}
```

#### 3. `reselect` (Child $\to$ Parent, Recovery only)
```json
{
  "type": "reselect",
  "schema_version": 1,
  "nonce": "e92a...",
  "reason_code": "active_slot_repaired",
  "active_slot_id": "2c5e..."
}
```

#### 4. `result` (Child $\to$ Parent $\to$ Stdout)
```json
{
  "type": "result",
  "schema_version": 1,
  "nonce": "e92a...",
  "operation": "advance",
  "state": "updated",
  "reason_code": "ok",
  "version": "1.1.0",
  "slot_id": "2c5e..."
}
```

---

## 4. Linux Lifecycle Hooks and Launcher Model

Both the controller and the launcher share a single unified build artifact:
- `launcher/acornfox-host-launcher`
- `controller/acornfox-host-update`

### WithLauncherFD Execution
Rather than reopening paths from disk, `Hooks.Stop`, `Hooks.Start`, and `Hooks.Probe` invoke `view.WithLauncherFD(ctx, callback)`. The callback directly executes the verified open file descriptor via `/proc/self/fd/3`, guaranteeing that on-disk pathname modifications cannot tamper with the executed binary.

### Service Lifecycle Rules
- **Never Stopped**: `docker.service`, `postgresql.service`, and `acornfox-upgrade-safe.target` are strictly preserved and never stopped.
- **Stop Procedure**: Application units (`acornfox-server`, `acornfox-agent`, `acornfox-caddy`, `acornfox-build-network`, `acornfox-buildkit`, `acornfox-runtime-network`, and optional units) are stopped in reverse dependency order. If ANY required stop command fails or any unit remains active, `RunSlotStop` fails immediately, preventing active slot activation. Port 8080 must be fully released before completion.
- **Start & Profile Restoration**: Starts required application units. Optional units (such as `acornfox-edge.service` and `acornfox-healthcheck.timer`) are queried via `systemctl is-enabled`; if enabled, they are restarted, restoring the exact deployment profile without creating new ledgers.
- **Probe Verification**: Confirms all required units and enabled optional units are active, and performs loopback HTTP health probes against `127.0.0.1:18481` (`/healthz`, `/readyz`) and `127.0.0.1:8080` (`/api/v1/acornfox/setup`).

---

## 5. Failure and Rollback Guarantees

1. **Deadlock Prevention**: The slot lock is acquired exclusively during `OpenActiveControllerReadOnly`. It is released before `admit-v1` is sent. A child process never contends for the slot lock while the parent waits.
2. **Process Ownership**: Child processes run in their own process group (`Setpgid: true`) with `Pdeathsig: syscall.SIGKILL` on Linux. All socket I/O and process wait operations have bounded deadlines. On timeout, signal, or protocol violation, `killProcessGroup` sends `SIGKILL` to the entire process group and confirms process reaping. If a child fails to terminate within the deadline, a typed `ErrChildRetained` error is returned.
3. **Fail-Closed Configuration**: Configuration files and invocation lockfiles are checked via `internal/hostconfig` using complete ancestor directory verification, post-open/post-lock identity revalidation against pathnames, `O_NOFOLLOW`, single link checks, 0600 permissions, root ownership, and strict canonical JSON byte equality.
