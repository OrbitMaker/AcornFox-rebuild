# M2 Agent deploy-group fixtures

These fixtures are deterministic, credential-free JSON inputs for the M2
`runtime.deploy_group` capability boundary. Request files are Agent v1
`task_request` envelopes. Their `payload.parameters` value is the typed
`DeployGroupRequest` shape: `deployment_id`, a complete digest-only `spec`,
and an `operation` context. The successful observation fixture carries the
aggregate `ServiceGroupRuntimeObservation` in the Agent observation
`payload.details` object.

The `capabilities` member is fixture metadata used by the handshake/test
harness. It is not a secret or a grant. A controller must negotiate the
runtime-group capabilities before accepting a group task; it must not infer
them from the request and must fail closed for an old Agent.

All timestamps, IDs, image digests, ports, and evidence references are fixed.
The image strings use the reserved `example.test` domain and the repeated
SHA-256 values are test vectors only. No fixture contains a real credential.

| Fixture | Expected result | Gate / invariant |
| --- | --- | --- |
| `deploy-group-request-valid.json` | accept | Complete two-service aggregate: stateful `db` plus ingress `web`, healthy dependency, retained named volume, secret reference, and initial rollout. |
| `deploy-group-result-valid.json` | accept | Version 1.1 task result with one idempotent successful completion and redacted evidence references. |
| `deploy-group-observations-valid.json` | accept | Version 1.1 aggregate observation: both services healthy/serving, limits and facts read back, effect known. |
| `deploy-group-request-old-agent-missing-capability.json` | reject `unsupported_capability` | Version 1.0 Agent advertises only M1 capabilities. A group request must not silently downgrade to a single-service deploy. |
| `deploy-group-request-unknown-security-field.json` | reject unknown security field | `capability_grant` is an unknown security-sensitive envelope field; it must not be ignored. |
| `deploy-group-request-missing-optional.json` | accept with defaults | Optional command, environment, healthcheck, volumes, and rollout flags are omitted; required fields remain explicit. |
| `deploy-group-request-incompatible-major.json` | reject incompatible major | Protocol `2.0` must be rejected before any task or runtime side effect. |
| `deploy-group-request-duplicate-service.json` | reject duplicate service | The runtime service list contains two `web` entries; names are unique identity keys. |
| `deploy-group-request-digest-tag-drift.json` | reject digest drift | The request records a tag and its first digest, while `registry_digest_after_tag_update` differs. A tag must never override the immutable Release digest. |
| `deploy-group-request-plaintext-secret.json` | reject plaintext secret | A secret environment entry supplies both a reference and a fixture-only plaintext marker; only `secret_ref` is permitted. |

## Harness rules

1. Decode the outer envelope with the Agent protocol compatibility gate before
   decoding `payload.parameters`. Unknown security-like fields, incompatible
   major versions, and missing negotiated capabilities must fail closed.
2. Decode the nested service-group spec with strict unknown-field handling.
   Validate all service names, digest-only images, resource limits, dependency
   conditions, volume claims, and rollout policy before dispatch.
3. Treat `registry_digest_after_tag_update` as a deterministic resolver
   response for `registry_reference`; it intentionally differs from the
   pinned Release digest in the fixture. The expected action is rejection,
   not retagging or silent replacement.
4. Treat `fixture-plaintext-must-reject` as a non-secret validation marker.
   Tests must assert that it is rejected and must not copy it into logs,
   images, environment persistence, audit, SSE, or Agent context.

The fixtures contain no host paths, Docker socket, devices, privileged flags,
network namespace requests, registry passwords, tokens, private keys, or
production endpoints.
