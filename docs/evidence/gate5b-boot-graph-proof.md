# Gate5B Ubuntu boot-graph acceptance — blocked

Date: 2026-08-30

This is failure evidence, not a passing acceptance record.  It records a real
Ubuntu 24.04 systemd result that blocks E1 boot-graph activation.

## Isolated environment

- Host: documented development libvirt host `ubuntu-MS-7B89`, reached through
  the existing IDC ProxyCommand entrypoint.
- Guest: disposable Ubuntu 24.04 amd64 cloud-image clone with 4 vCPU, 8192 MiB
  memory, a 100 GiB thin qcow2 overlay, autostart disabled, and an isolated
  no-forward libvirt network.
- Resource prefix: `opencard-g5b-20260830-a01`.
- The base image was read-only; the task SSH key, cloud-init seed, overlay,
  network, storage pool, and domain were all task-scoped.

## Commands and observed result

The guest installed these canonical artifacts byte-for-byte from the repository:

- `open-card-upgrade-recover.service`
- `open-card-upgrade-safe.target`
- `open-card-upgrade-finalize.service`
- `open-card-edge.service.d/10-upgrade-marker.conf`

It added harmless same-name dummy business units which only create files under
the task state root, enabled the safe target and the five units, and ran
`systemd-analyze verify` against the three canonical units and five business
units.  Static verification passed; the guest then exercised the actual
marker-absent boot path.

With `/var/lib/open-card/upgrade-in-progress` absent, the guest ran:

```text
systemctl start open-card-upgrade-safe.target \
  open-card-buildkit.service open-card-caddy.service \
  open-card-server.service open-card-agent.service open-card-edge.service
```

Systemd returned:

```text
A dependency job for open-card-upgrade-safe.target failed.
```

The cause is the current unit graph:

```text
open-card-upgrade-safe.target:
  Requires=open-card-upgrade-recover.service

open-card-upgrade-recover.service:
  ConditionPathExists=/var/lib/open-card/upgrade-in-progress
```

When the marker is absent, systemd skips the recovery service due to its
condition.  A `Requires=` dependency on that skipped unit then fails the safe
target, preventing normal business-service boot.  This is a real Linux/systemd
behavior, not a fixture inference.

## Safety and cleanup

The harness stopped after this marker-absent defect; it did not claim the
marker-present, finalizer, or reboot scenarios as passed.  Cleanup verified:

```text
G5B_TASK_RESOURCES_RECLAIMED=PASS
```

No prefixed domain, network, storage pool, qcow2, task root, key, seed, or
bridge remained.  Existing host domains, networks, and pools were not changed.
No cloud, DNS, firewall, public port, or production write occurred.

## Required repair before rerun

Repair the E1 unit relationship so a marker-absent recovery condition cannot
make `open-card-upgrade-safe.target` fail.  Re-run the complete isolated guest
matrix—including marker-present prepare/finalize failures and an actual
reboot—after an independently reviewed product-unit change.
