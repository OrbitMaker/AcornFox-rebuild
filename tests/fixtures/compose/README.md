# M2 Compose fixtures

These files are deterministic JSON-shaped Compose inputs for the M2 import and
runtime tests. They are safe test data only: registry names are reserved
`example.test` placeholders, image references are digest-pinned, and no fixture
should be passed to a real Compose deployment.

The positive fixtures contain only the supported import subset. They use target
ports without host publication, named volumes instead of host paths, private
networks, and explicit dependency conditions. The negative fixtures each carry
one policy or validation violation and must fail closed without producing a
`ServiceGroup`.

| Fixture | Class | Expected result | M2 test IDs |
| --- | --- | --- | --- |
| `supported-multiservice.json` | four-service build/image mix | imports to a deterministic DAG; only `web` has an ingress target; named volume and limits are retained | `SCHEMA-SERVICE-001`, `SCHEMA-COMP-001`, `UNIT-DAG-001`, `E2E-COMPOSE-001`, `CT-RUNTIME-001`, `CT-VOLUME-001`, `RUNTIME-INT-001`, `VOL-INT-001`, `ROLL-001` |
| `prebuilt-digest-mix.json` | four prebuilt services from fake registries | every service uses an immutable `@sha256:` reference; only `frontend` has an ingress target | `SCHEMA-COMP-001`, `CT-IMAGE-001`, `E2E-IMAGE-001`, `IMG-INT-001`, `IMG-INT-002`, `SCHEMA-RELEASE-001` |
| `negative-privileged.json` | forbidden `privileged` field | reject the service before normalization | `SEC-COMP-001` |
| `negative-host-network.json` | `network_mode: host` | reject host networking | `SEC-COMP-001` |
| `negative-host-pid.json` | `pid: host` | reject host PID namespace sharing | `SEC-COMP-001` |
| `negative-host-ipc.json` | `ipc: host` | reject host IPC namespace sharing | `SEC-COMP-001` |
| `negative-host-uts.json` | `uts: host` | reject host UTS namespace sharing | `SEC-COMP-001` |
| `negative-docker-socket.json` | Docker socket bind | reject socket access and host bind type | `SEC-COMP-002` |
| `negative-host-bind.json` | arbitrary absolute host bind | reject dangerous host filesystem access | `SEC-COMP-002` |
| `negative-device.json` | `/dev/kvm` device mapping | reject device exposure | `SEC-COMP-002` |
| `negative-cap-add.json` | `cap_add: SYS_ADMIN` | reject capability elevation | `SEC-COMP-002` |
| `negative-cap-drop.json` | `cap_drop: ALL` | reject capability mutation, even when it appears restrictive | `SEC-COMP-002` |
| `negative-unknown-field.json` | unknown service key `mystery` | fail closed and report `services.app.mystery` | `SCHEMA-COMP-002`, `SEC-COMP-003` |
| `negative-unknown-nested-field.json` | unknown nested build key | fail closed and report `services.app.build.mystery` | `SCHEMA-COMP-002`, `SEC-COMP-003` |
| `negative-cycle-self.json` | self dependency | reject the invalid dependency target | `UNIT-DAG-002`, `E2E-COMPOSE-001` |
| `negative-cycle-two-node.json` | `api ↔ worker` dependency cycle | reject with a cycle error from dependency ordering | `UNIT-DAG-002`, `E2E-COMPOSE-001`, `FAULT-RUNTIME-001` |
| `negative-published-host-port.json` | published host port `18080:8080` | reject host port publication; only target-port routing is allowed | `SCHEMA-COMP-001`, `E2E-COMPOSE-001` |

The M2 test-spec references are from `.omx/plans/open-card-mvp-test-spec.md`.
`SCHEMA-COMP-001` covers the supported port shape; the published-port fixture
is its explicit fail-closed boundary case. `negative-cycle-self.json` can be
rejected during service validation, while the two-node fixture reaches the
topological cycle detector.
