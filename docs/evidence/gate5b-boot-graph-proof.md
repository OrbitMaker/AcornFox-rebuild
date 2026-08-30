# Gate5B Ubuntu boot-graph acceptance — PASS

Date: 2026-08-30

This record accepts the Gate5B **systemd boot graph and marker boundary** on a
real Ubuntu 24.04 guest. It does not replace the separate real PostgreSQL
upgrade evidence and does not claim a production deployment.

## Accepted source and byte binding

- Source commit: `4ddcd1b6fda8649fe923a855551187af288c4725`.
- The harness was intentionally uncommitted during this run.  It copied and
  verified the actual local bytes below before the guest installed anything;
  this document therefore binds the run to both the current repository commit
  and the subsequently committed harness bytes.
- Guest verifier manifest:

  ```text
  5dd163389068b4ad0e5b153bc812b043f8dcc576820f0314d842e28be72ac894  clean_worker_gate5b_boot_guest.sh
  42b4ef707f4c4efce74c16a70b9b012dd46ad4b3960e448350418ae02cfc80d8  devbox_gate5b_boot_graph.sh
  086ab7b25d6f779bb4df2dd0d6f5e0b4376fd157b6ccc35fcff6eeead775bb5c  systemd/open-card-upgrade-recover.service
  0de4a37d59566971cf11606f9e584ca2d9325bf6d8ca217325d382f796960cfd  systemd/open-card-upgrade-safe.target
  0fbbda51c9c1b1c2c2600ee09b0cf4e05e99db26e500a6e2c6fe34ec31c5aa63  systemd/open-card-upgrade-finalize.service
  af0cf74314389ca5c9c2a3ca541679f65670ea95eebb12a0ce75eba71a72fbd8  systemd/open-card-edge.service.d/10-upgrade-marker.conf
  ```

  The guest retained `source-commit.txt`, `source-manifest.sha256`, and a
  successful `sha256sum -c` transcript in its evidence before any unit was
  copied to `/etc/systemd/system`.
- The recovery unit always runs as the safe target's required dependency.
- Marker absence is decided under the same global flock used by upgrades and
  returns an explicit no-op.
- Ordinary mutable CLI operations remain unavailable until the safe target is
  active.

The previous real Ubuntu run proved that a condition-skipped required recovery
service fails `open-card-upgrade-safe.target`. That failed result is retained
in commit `d74e43da94489613a2d3ef17287d1d178d6a7f44`; the repaired run below uses
the same isolated lifecycle harness.

## Isolated environment

- Host: documented development libvirt host `ubuntu-MS-7B89`, reached through
  the existing IDC ProxyCommand entrypoint.
- Guest: Ubuntu 24.04.4 LTS, x86_64, 4 vCPU, 7941 MiB visible memory, and a
  100 GiB thin qcow2 overlay.
- Network: task-only libvirt network with no forwarding.
- Resource prefix: `opencard-g5b-20260830-a01`.
- Autostart: disabled.
- Base image: existing Ubuntu 24.04 cloud image, used read-only.

The task SSH key, known-hosts file, cloud-init seed, overlay, network, pool,
domain, and evidence root were unique to this run.

## Real systemd evidence

The guest installed the following canonical repository artifacts byte-for-byte:

- `open-card-upgrade-recover.service`
- `open-card-upgrade-safe.target`
- `open-card-upgrade-finalize.service`
- `open-card-edge.service.d/10-upgrade-marker.conf`

It enabled the safe target plus harmless same-name dummy business units, then
ran `systemd-analyze verify` and exercised the actual systemd transactions.

Accepted scenarios:

1. **Marker absent:** required prepare returned its explicit no-op; the safe
   target and all benign business units started.
2. **Prepare failure:** the required recovery service failed; the safe target
   and business units stayed inactive and the marker remained.
3. **Finalizer failure:** the marker remained and Edge stayed inactive. The
   direct `systemctl start open-card-edge.service` was condition-skipped:
   `ActiveState=inactive`, `SubState=dead`, `ConditionResult=no`. Ubuntu
   systemd returned client status `0` for that skip, so the accepted invariant
   is the inactive unit and retained marker rather than the client status.
   `ss -lntup` recorded no listener on ports 80 or 443. The guest's SSH
   listener on port 22 remained present and is intentionally not claimed
   absent.
4. **Terminal success:** prepare and finalizer succeeded, the marker was
   removed, and Edge could start only afterward.
5. **Real reboot with a prepare-failure marker:** prepare failed again after
   reboot, the safe target did not activate, all business units remained
   inactive, and Edge remained unavailable.

The guest summary was:

```text
guest_os=Ubuntu 24.04.4 LTS
arch=x86_64
memory_mib=7941
vcpus=4
initial=PASS
reboot_marker_prepare_failure=PASS
public_listeners=none
```

## Safety and cleanup

Before task-root creation, the harness created a root-owned, 0600 exact claim
at `/var/lib/libvirt/images/.opencard-g5b-20260830-a01.claim`. Its contents
bound the prefix, domain, network, pool, root, and bridge. Preflight rejected
an existing claim, task root, domain, network, pool, or `virbr-g5ba01` bridge.
Cleanup trusted this claim rather than the guest task marker, so it remained
authorized if the guest marker was absent; no resource is deleted without an
exact matching claim.

After evidence collection the harness destroyed and undefined the exact task
domain, network, and pool, deleted the exact task root, and removed the claim
last. It then rechecked all six absences and compared the domain/network/pool/
bridge inventory byte-for-byte to the pre-create snapshot.

Final checks proved:

```text
DOMAIN_ABSENT
NET_ABSENT
POOL_ABSENT
ROOT_ABSENT
BRIDGE_ABSENT
CLAIM_ABSENT
HOST_INVENTORY_MATCH
```

No existing VM, storage pool, network, bridge, cloud resource, DNS record,
firewall rule, or public endpoint was changed.

## Remaining Gate5B boundary

This proof validates the real systemd graph, marker gating, failure propagation,
and reboot behavior with safe dummy services. Gate5B still requires the clean
Ubuntu RC0-to-RC1 product upgrade, real service health, kill/reboot points, and
public Edge checks before production enablement or removal of the
`upgrade.sh` hard refusal.
