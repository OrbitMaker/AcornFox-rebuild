# ADR-0008: REST/OpenAPI/SSE plus signed webhooks

- Status: Accepted; G8 compatibility Spike passed
- Gate: G8 / S0

Use REST JSON described by OpenAPI 3.1 for UI/admin operations and SSE for
event-derived UI state. Use the versioned mTLS Agent protocol from ADR-0002 and
HMAC-SHA256 JSON webhooks. SSE uses event IDs, `Last-Event-ID`, 15-second
heartbeats and an initial 24-hour replay window. Webhook initial timeouts are
three seconds connect/ten seconds total with 1/5/30-minute retries and a
24-hour event-ID dedupe window.

Polling is the UI fallback. OpenAPI type generation, fixed webhook vectors,
repository-backed 24-hour SSE replay, 15-second heartbeats and replay after a
control-plane process restart pass. REST, SSE and Agent support explicit 1.0
(N-1) / 1.1 (N) negotiation; legacy `v1` normalizes to 1.0, capability loss is
reported, poll/events remain bound to the connecting mTLS certificate,
incompatible major versions return an explicit rejection, and security-like
unknown fields fail closed. Additive migration 0007 preserves old
task/outbox readers while current writes carry 1.1 schema/wire versions.
