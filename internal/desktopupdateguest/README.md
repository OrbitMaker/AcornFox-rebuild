# Privileged guest update transport

This Linux core reuses `desktopupdate.VerifyHostBundle`, the original signed
index and complete payload. It extracts only the six flat backend candidate
files plus the hash-bound successor helper from the signed backend archive.
It invokes the existing `repository-upgrade` and pending recovery commands.
It does not implement backend rollback, migration, release GC or data cleanup.

Production configuration is provisioned separately, never from a request:

- `/etc/acornfox-host/guest-update-policy.json`: canonical JSON `Policy`, root:root 0600.
- `/etc/acornfox-host/guest-instance.json`: canonical JSON `Instance`, root:root 0600.
- `/var/lib/acornfox-host/guest-update`: root-owned directory, no group/other write.
- `/usr/local/libexec/acornfox-guest-update`: root:root 0755 fixed executable.

There are no environment, command-line public-key, command or target-directory
overrides. Missing policy yields `not-configured`. The policy uses the HOST
OS/architecture and channel, while the executor itself runs on Linux. All
traversed production directories must be root-owned and not writable by other
users. Unit names for later service integration must use
`com.acornfox.host-update...`, not the backend's closed `acornfox-*` namespace.

Native identity remains authoritative. Mac and WSL both read
`/var/lib/acornfox-desktop/owner-marker`, but parse their respective existing
`{product,instance}` and `{product,host_uuid}` schemas. The root Instance record
pins its exact SHA256 and NativeID. Linux reads a separately provisioned
`/etc/acornfox-host/linux-owner-marker` with `{product,instance}`. InstanceID is
SHA256 of UTF-8 `kind + ":" + NativeID` (kind is `mac-managed`, `wsl-managed` or
`linux-local`). This mapping must also be used by the host adapter. No marker,
seed or disk is rewritten here.

Commands emit bounded JSON with stable result/error codes:

- `observe [ATTEMPT_ID]`: current helper contract, backend runtime/configuration,
  strict local readiness and absence of pending upgrade/rollover state.
- `status ATTEMPT_ID`: transport receipt only; not backend health evidence.
- `submit`: stdin contains one canonical JSON `SubmitRequest` line, followed by
  exactly `payload_size` bytes and EOF. `envelope` is the original envelope as
  base64 JSON bytes. `intent` is the existing `HostUpgradeIntent` type.
- `recover ATTEMPT_ID`: wakes the fixed detached worker for a durable job.
- `run ATTEMPT_ID`: fixed worker entry; only queued verified jobs can upgrade.
  Previously started jobs use recovery instead of replaying upgrade.

A receipt is written and fsynced before starting the worker with a new session,
clean environment and detached stdio. Duplicate IDs must match the exact
intent and envelope. Accepted sequence/payload floors persist independently
of installed state. A queued job still needs a currently valid index; already
started jobs reverify using the root-recorded acceptance time for recovery.
State snapshots carry a monotonic revision and the previous committed SHA.
Recovery publishes only a fully validated legal next snapshot. A torn snapshot
is preserved in a single root-owned `state-quarantine` slot; it is never parsed
as authority and does not block subsequent jobs. A second torn snapshot while
that slot is occupied fails closed. If the queued-receipt write was interrupted,
only an explicit retry of the same ID/envelope can reuse the completed intake,
after revalidating both payload streams and the exact extracted inventory.

The worker's boot, PID, process-start and process-group identities prevent
recovery from racing a still-live worker or its successor child.

`upgraded` requires observed target binding, strict readiness and finalized
backend state; an exit code alone is insufficient. `rolled-back` additionally
requires the existing backend's typed rollback result. Interrupted recovery
which only proves a healthy old binding remains `unknown`; it does not assert
that the candidate was tried or found faulty.

## Validation and remaining integration

Linux root tests exercise real filesystem ownership, signatures, bundle bytes,
fd execution, detached child processes, restart/replay and bounded receipts.
Their backend adapter is a fixture, so these tests do not prove an actual
system upgrade, rollback, VZ, WSL or desktop launcher update.

Service/provisioning, host transport adapters and three-platform native glue
are intentionally outside this package. No production key/URL is invented.
Receipt retention and quarantined intake directories are capped at 32. At the
limit, new jobs fail closed with `retention-full`. Precise terminal-job inventory
GC and repair of incomplete intake or an occupied quarantine after a second
torn state write are still required for
indefinite production operation; no unknown file is deleted or promoted.
