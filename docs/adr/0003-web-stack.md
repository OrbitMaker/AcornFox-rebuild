# ADR-0003: React, TypeScript, Vite and Semi Design

- Status: Accepted; G3 Spike locally passing
- Gate: G3 / S3

Use React 18.3.1, TypeScript 5.9.2, Vite 8.2.2 and Semi Design 2.102.0 in the
formal `web/` application. Pin the complete dependency graph in
`package-lock.json`. Generate types from the checked-in OpenAPI description and
serve the production build from the control plane later. Development and
preview servers bind loopback by default on shared machines.

The first shell covers the final MVP navigation, application list, creation
wizard, and the five event-derived publishing states. AI chat is not part of
this gate. Remaining measurement risks are bundle size/accessibility and the
upstream lottie direct-eval warning; either can trigger a component-library ADR
without replacing React/Vite.
