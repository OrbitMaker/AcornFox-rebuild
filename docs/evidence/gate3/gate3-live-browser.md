# Gate 3 Live browser acceptance

This is a local-only evidence packet for G3-08. It uses the Live web build,
same-origin `/api/v1`, a task-local PostgreSQL cluster, and loopback high ports.
It does not contact Tencent Cloud, public DNS, Caddy, systemd, or an online
service.

## Reproduction boundary

- Repository HEAD for the final verified backend pass: `6985ea4`.
  G3D system status is `bbd6580`; G3E application projection is `f43dc5b`;
  G3F publish projection is `512e9b6`; the G3F publish facade is `957a988`;
  and final publish-request hardening is `6985ea4`.
- Web origin: `https://127.0.0.1:58084` (task-local self-signed certificate).
- API origin: `http://127.0.0.1:58083`.
- PostgreSQL: task-local cluster on `127.0.0.1:55483`.
- Browser: Playwright CLI session `gate3-08-publish`; no `@playwright/test`.
- Temporary upload fixture: generated under `/tmp/opencard-g3-08-e2e.*` by
  `tests/e2e/gate3_live_browser.sh --keep-fixture`, not stored here.

Commands used:

```text
VITE_API_MODE=live VITE_API_BASE_URL=/api/v1 npm --prefix web run build
npm --prefix web test -- --run src/api/client.test.ts
npm --prefix web run lint
npm --prefix web run typecheck
npm --prefix web audit --omit=dev
bash -n tests/e2e/gate3_live_browser.sh
node --test scripts/g3/live_web_proxy_contract.test.mjs
tests/e2e/gate3_live_browser.sh --origin https://127.0.0.1:58084 --api-origin http://127.0.0.1:58083 --evidence-dir "$PWD/docs/evidence/gate3" --task-prefix opencard-g3-08-e2e --keep-fixture
```

The preflight machine summary is [preflight.ndjson](./preflight.ndjson).

## Browser results

| Check | Result | Evidence / boundary |
| --- | --- | --- |
| Unauthenticated Live entry | PASS | [01-unauthenticated.png](./01-unauthenticated.png); session request is 401 and only login is shown. |
| Login | PASS | UI login reached the authenticated console after fixing the browser `fetch` binding and sending only the frozen password field. |
| Session refresh | PASS | [03-session-refresh.png](./03-session-refresh.png); reload retained the authenticated session. |
| Empty application list | PASS | [04-applications-empty.png](./04-applications-empty.png). |
| Invalid application deep link | PASS | `?application=missing-g3-08` was cleared and returned to the overview. |
| Real browser archive upload | PASS | [05-upload-ready.png](./05-upload-ready.png); one `.zip`, 2,267 bytes, server status `ready`, digest `sha256:380263507dfbaa494d6d4ce578e292410e88229d78f7e7a0cc58ba92adb70b22`. |
| Upload-backed application create | PASS | The real browser upload-backed app lists as `归档上传 upload:<id>` and detail renders source upload ID plus access facts. |
| Git source entry | PASS | [08-git-boundary.png](./08-git-boundary.png); UI states public HTTPS + explicit ref only, and private repositories, SSH, and credentials unsupported. No public repository fetch was attempted because resolver configuration is intentionally absent. |
| Domain workspace | PASS / LIMITED | [06-domains-unavailable.png](./06-domains-unavailable.png); real API/UI show unavailable platform state, empty application domains, no IP fallback, and no false success. |
| Logout | PASS | [09-logout.png](./09-logout.png); UI returned to login and local protected state was cleared. |
| Unpublished status | PASS | `PublishingStatusTag/Track` now show `未发布` / `尚未发起发布` when no publishing fact exists; a succeeded event does not change runtime readiness. |
| Publish submission fail-closed | PASS / LIMITED | [12-publish-not-accepted.png](./12-publish-not-accepted.png); the real Live publish request returned HTTP 503 before capacity acceptance because the Darwin host has no `/proc/meminfo`; the UI showed `发布未完成` and a safe unavailable message. After the settled list refresh, the row remained `未发布`, runtime remained `未就绪`, and the footer remained `0 个应用运行正常`. DB checks were `m1_publish_requests=0` and `publish.*=0`, proving this was not accepted and must not be called `publish.failed`. |
| 401 | PASS | Unauthenticated session and post-logout behavior. |
| 409 | UNKNOWN | No safe local fixture was available without creating a conflicting durable request. |
| 422 | UNKNOWN | The attempted invalid hostname reached a dependency-unavailable path (503) before validation; no production fixture was added. |
| 429 | UNKNOWN | Not induced because doing so would lock the task administrator source and add avoidable state. |
| 5xx | PASS / LIMITED | The publish endpoint returned HTTP 503 with a safe UI error and no durable publish request/event; other 5xx variants were not induced. |
| SSE persisted replay/reconnect | PASS / LIMITED | Deterministic client tests cover connecting/connected/offline/retrying/401/closed, Last-Event-ID, deduplication, and bounded backoff. A real publish stream was not claimed because this local request was rejected before a publish operation existed; real publish stream success/failure remains Gate 6 staging. Operations facts UI remains unavailable in M1-only mode. |
| System settings status panel | PASS | [10-system-settings-live.png](./10-system-settings-live.png); authenticated API facts show single-node readiness, explicit unconfigured platform domain, Webhook count 0/unconfigured, and backup/alerts `not_installed`; password rotation remains visible while AI is unavailable. |

## Product fixes made for this acceptance

- The Live REST adapter now sends only `{password}` to the frozen login
  endpoint; the UI username remains a display/input field and is not sent.
- The Live REST adapter binds the browser-native `fetch` before invoking it as
  a client member; this fixes the browser-only `Illegal invocation` failure.
- The Git wizard no longer presents the obsolete 501/unavailable path. Its
  boundary is public HTTPS + explicit ref only; private/SSH/credentials remain
  explicitly unsupported.
- The create confirmation copy now says the application/source are created
  first, and publish settings must be submitted separately before publish
  states appear.
- Publish settled refreshes the list without unmounting the detail panel, so a
  safe local 503 error remains visible while the application facts stay
  unchanged.

## Remaining limits and untested boundaries

1. The local Darwin host rejects the publish request during capacity preflight,
   before `m1_publish_requests`/`publish.*` are written; real publish stream
   success/failure needs a Linux-capable staging worker and remains Gate 6.
2. Operations facts/Webhook composition are not enabled by this local process;
   deterministic SSE reconnect is proven, but the full operations UI remains
   limited.
3. 409/422/429 browser fixtures, public Git fetch, real DNS verification,
   certificate issuance, external probe, and production deployment were not
   attempted.
