# ADR-0001: Go modular monolith for the control plane

- Status: Accepted; G1 Spike passed
- Gate: G1 / S0

Use a Go modular monolith with `net/http` at the process boundary. Keep the
module language level at Go 1.25 while release builds use a hermetic Go 1.27.0
toolchain. Produce CGO-free Linux amd64 and arm64 binaries. This avoids a
framework dependency before the API shape is stable and permits one-process
self-deployment.

Go 1.27.0 was the current stable release when this ADR was recorded. The module
language level is now Go 1.25 and the verified Mac toolchain is Go 1.25.7;
host toolchains are not the release baseline. `SPIKE-S0-GO` passed Linux
amd64/arm64 cross-builds, full race/vet, 20 concurrent requests, 704 ms cold
start and 13,504 KiB idle RSS after durable Agent/controller and observability
integration.

Fallback: TypeScript modular monolith only if the Go Spike misses a required
SDK or maintenance criterion. That fallback does not change the Agent decision.
