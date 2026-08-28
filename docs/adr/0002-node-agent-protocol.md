# ADR-0002: Agent-initiated mTLS HTTPS protocol

- Status: Accepted fallback; transport/read-only Spike passed
- Gate: G2 / S0

Use a versioned JSON message schema over Agent-initiated mTLS HTTPS long poll
plus SSE/log streaming. This is the plan's permitted fallback from Connect/gRPC
and keeps M0 dependency-free. The control plane never exposes the Docker API;
the Agent accepts only typed allowlisted tasks and rejects arbitrary shell.

Initial parameters are TLS 1.2 minimum, 24-hour certificates with rotation at
50% lifetime, 5-second heartbeats, unknown after three misses, capped reconnect
backoff of 1/2/4/8/16/30 seconds, and task cancellation within five seconds.
`SPIKE-S0-AGENT-OUTBOUND` now proves Agent-initiated strict mTLS connect/poll,
pre-registered certificate-to-node binding, heartbeat/unknown projection,
disconnect replay and message idempotency. `SPIKE-S0-AGENT-DOCKER-FACTS`
proves the Agent reads only allowlisted `/version` and `/info` facts without
changing Docker inventory. The durable dispatch/result bridge passes against
PostgreSQL under `SPIKE-S1-CONTROLLER-WORKER`; joint installed-process testing,
certificate rotation and mutating RuntimeDriver tasks remain outside this
passed slice.

Fallback: revisit Connect over HTTP/2 if long polling cannot meet measured log
streaming or compatibility needs. The wire objects and error taxonomy remain.
