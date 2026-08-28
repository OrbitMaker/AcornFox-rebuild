# Open Card web

This is the formal React + TypeScript + Vite + Semi Design control-plane UI
for the single-node MVP. The old `prototype/` pages remain visual references;
they are not imported into this app.

## API boundary

`src/api/client.ts` defines the stable UI-facing `ApiClient` contract. The live
adapter uses REST JSON for applications and SSE for publishing events. The
event projection accepts only the five product states:

`preparing → building → deploying → succeeded | failed`

`VITE_API_MODE=stub` (the default until the control-plane API is available)
uses `StubApiClient`; `VITE_API_MODE=live` uses `RestApiClient` and
`VITE_API_BASE_URL` (default `/api/v1`). The stub emits the same typed event
shape and is not an AI/chat implementation.

When `api/openapi/openapi.yaml` is present, run:

```sh
npm run generate:api
```

The command delegates schema generation to the pinned `openapi-typescript`
dependency and writes the ignored `src/api/generated-schema.ts` artifact.
The hand-written adapter remains the compatibility seam until the generated
operation paths are frozen by the control-plane API. If the schema is absent,
the command exits successfully and leaves the typed stub intact, so a clean
M0 frontend build does not depend on an unfinished backend directory.

## Local checks

```sh
npm install
npm run lint
npm run typecheck
npm test
npm run build
```
