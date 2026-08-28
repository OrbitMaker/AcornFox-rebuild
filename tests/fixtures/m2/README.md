# Open Card M2 guest fixtures

This directory is the deterministic input set for the real M2 clean-worker
acceptance run.  It is data only: it contains no credentials, host paths,
Docker socket references, or mutable image tags that are accepted as runtime
identity.

The guest runner is `tests/spikes/clean_worker_m2_guest.sh`.  The runner is
root-only because it must inspect the task VM's Docker facts, systemd
recovery, loopback traffic, and PostgreSQL projections.  It never writes a
control-plane outcome directly: state changes are made through the public
HTTP API, the mTLS Agent, Docker operations scoped by the task label, and the
fixture registry's HTTP API.

## Fixture layout

| Path | Purpose |
| --- | --- |
| `compose/mixed-services.json` | Four-service Compose subset: built `frontend`/`api`, private-registry `db`, and built `worker`; only `frontend` is ingress. |
| `compose/mixed-services-v2.json` | Deterministic frontend content change for rolling update. |
| `compose/optional-worker.json` | Same topology with an explicitly optional worker for failure semantics. |
| `compose/invalid-*.json` | One-policy-per-file negative Compose cases. |
| `services/*` | Scratch Dockerfile contexts. The guest runner supplies the canonical static-server binary and service marker files. |
| `registry_fixture.py` | Minimal local OCI Distribution fixture. It serves public and Basic-auth private repositories, digest-pinned manifests, and a controlled tag move. |
| `registry/README.md` | Registry fixture protocol and digest expectations. |
| `manifest.sha256` | SHA-256 manifest for every checked-in M2 fixture; validate from the repository root before creating the canonical guest bundle. |

The registry listens only on `127.0.0.1` on the task VM and stores its data
under the task-prefixed evidence/work directory.  The runner requires the
fixture to be addressed by an immutable repository digest after resolution;
`stable` is used only as the input to the resolver test.  The private token is
generated at runtime, materialized through the SecretReference API, and is
never put in this tree or in command-line arguments.

## Guest API contract

The runner uses these public endpoints.  Deployments may expose equivalent
routes only through explicit environment overrides in the runner; an absent
route is a failed test, not a skip.

* `GET /api/v1/agents/capabilities` returns the negotiated aggregate runtime capability set; `POST /api/v1/agents/capabilities/legacy-negative` is a test-only capability negotiation request that must fail closed for an old Agent.
* `POST /api/v1/sources` accepts the multipart upload and returns `{source_revision}`; `POST /api/v1/service-groups/import` accepts `{application_id,environment_id,name,compose,source_revision_id}` and returns `{service_group,report}` with a canonical digest.
* `POST /api/v1/service-groups/{id}/releases` creates one immutable release from the normalized group and returns `{release}`.
* `POST /api/v1/service-groups/{id}/deployments` accepts `{release_id,rollout,operation}` and returns `{deployment,operation}`.
* `GET /api/v1/service-groups/{id}`, `/releases/{id}`, `/deployments/{id}`, and `/deployments/{id}/events` return durable projections/events.
* `POST /api/v1/images/resolve` accepts `{repository,tag,registry,secret_ref,platform}` and returns `{image}` with an immutable digest.
* `POST /api/v1/images/gc` accepts `{application_id,retain_successful:3}` and returns before/after image facts.
* `POST /api/v1/volumes/{id}/write-fixture` and `GET /api/v1/volumes/{id}/checksum` are task-fixture-only evidence helpers; ordinary application APIs must not expose host paths.
* `POST /api/v1/volumes/{id}/destroy` requires `{confirmation_token}`; deployment destroy defaults to retaining volumes.
* `POST /api/v1/rollouts/{deployment_id}` accepts a complete replacement release and returns the old/new traffic and health timeline.

All mutating requests carry an `Idempotency-Key`.  The runner validates the
same request replay and checks the durable release, task, event, container,
network, image, and volume projections after every operation.

## Security boundary

Do not add a real production registry, DNS name, certificate, cloud resource,
host mount, device, privileged flag, or Docker socket to these fixtures.  The
runner rejects any container outside `opencard-mvp-fa8f8eab` and removes only
exact task-prefixed registry resources during its exit trap.
