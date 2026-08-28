# Open Card MVP engineering ADRs

These records resolve the engineering defaults required by G1-G9. Their
status is deliberately independent from milestone acceptance: an ADR can pick
a direction while its Spike or environment gate remains incomplete. Runtime
claims require the corresponding evidence under `artifacts/mvp/`.

| Gate | ADR | Decision status | Spike status |
| --- | --- | --- | --- |
| G1 | [0001](0001-control-plane-language.md) | accepted | pending final measurements |
| G2 | [0002](0002-node-agent-protocol.md) | accepted fallback | pending mTLS integration |
| G3 | [0003](0003-web-stack.md) | accepted | local tests passing |
| G4 | [0004](0004-control-plane-database.md) | accepted | partial |
| G5 | [0005](0005-migrations.md) | accepted | migration cases passing |
| G6 | [0006](0006-observability-storage.md) | proposed | not run |
| G7 | [0007](0007-installation-service-model.md) | accepted target | clean Ubuntu 24.04 Spike passed |
| G8 | [0008](0008-api-and-events.md) | accepted | N/N-1 compatibility Spike passed |
| G9 | [0009](0009-task-and-event-model.md) | accepted | partial |
| S2 | [0010](0010-buildkit-backend-blocked.md) | isolated worker accepted | clean-worker Spike/recreate/reclaim passed; shared-host paths rejected |
