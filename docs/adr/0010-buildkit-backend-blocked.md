# ADR-0010: Use an isolated clean worker for real BuildKit acceptance

- Status: Resolved by isolated-worker Spike; shared-host backends rejected
- Gate: S2 / M0 → M1
- Verified: 2026-08-24

## Context

The MVP requires a local BuildKit backend with CPU, memory, disk, timeout,
concurrency, workspace, network and cleanup boundaries. The shared physical
development host must retain AppArmor/userns policy and must not run a
privileged BuildKit container or expose the Docker Socket to user builds.

## Evidence

The existing task-prefixed rootless BuildKit 0.32.2 container is non-privileged
but cannot start while `apparmor_restrict_unprivileged_userns=1`. Its safety
Spike proves a fail-closed stop; it does not prove a usable build backend.

A task-local, SHA-256-pinned buildx 0.36.1 also exercised Docker Engine 29.1.3's
integrated `docker` driver, which reports BuildKit 0.26.2. The candidate path:

- built and ran a task-labelled image;
- exposed neither `/var/run/docker.sock` nor a host mount inside the user build;
- blocked metadata access with build-step `--network=none`;
- cancelled a long build within five seconds and left no active build process;
- left AppArmor policy, non-task containers, VM inventory, protected services
  and the default route unchanged.

The same build requested `memory=64m`, `memory-swap=64m` and
`cpu-quota=50000`, but the build step observed:

```text
memory.max=max
cpu.max=max 100000
```

The default driver also uses the shared `moby` namespace/cache and reports its
worker network as `host`. Its cache cannot be safely pruned per Open Card task
without risking other workloads on this host.

Evidence: `artifacts/mvp/m0/SPIKE-S2-BUILDKIT/` and
`artifacts/mvp/m0/SPIKE-S2-BUILDX-INTEGRATED/`.

## Decision

Do not implement or accept a real M1 `BuildProvider` on either shared-host
backend. The accepted test backend is the exact task-owned clean VM described
below; M1 may start only against a comparably isolated endpoint.

The authorized clean worker used rootless BuildKit 0.32.2, one concurrent build,
an aggregate 512 MiB/50% CPU service cgroup, a 4 GiB BuildKit filesystem and a
libvirt network with neither forwarding nor an IP. The build-step PID was
observed in that cgroup. Network/metadata, Docker Socket, host mounts/devices,
secret leakage, timeout, failed output and workspace cleanup negatives passed;
OCI metadata returned an immutable digest.

The non-mutating preparation is now reproducible in
`deploy/worker/clean-worker-spec.json`,
`scripts/mvp/clean-worker-{preflight,acceptance,reclaim}.sh` and
`tests/spikes/clean_worker_spec.sh`. The checked-in specification remains a
non-mutating template, while the completed run used the Ubuntu released-image
SHA-256 `6e40c07a...a3733` and offline-bundle SHA-256
`3e5ddcfb...55158`. Delete/recreate reproduced S2; final reclaim removed all
domain/volume/pool/network/image/ISO/bundle resources and restored the exact
host baseline.

## Rejected alternatives

- Disable or weaken AppArmor/userns: violates the shared-host safety boundary.
- Run a privileged `docker-container` BuildKit worker: violates the explicit
  no-privileged requirement.
- Treat successful image output as S2 PASS: ignores missing resource and cache
  isolation and would turn weak evidence into a false capability claim.
- Prune the default Docker builder cache: may delete cache owned by unrelated
  workloads.
