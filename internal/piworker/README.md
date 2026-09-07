# AcornFox Pi worker

`acornfox-pi-worker` is a separate unprivileged service. It accepts one active control-plane connection on `/run/acornfox-pi/worker.sock`, launches one restricted Pi process only after a valid handshake, transparently relays Pi JSONL, and kills/reaps the process when the connection, run deadline, worker context, or Pi process ends. It never retries prompts or starts an idle Pi process.

The control plane writes one strict-LF handshake before creating `pirpc.NewTransport` on the returned connection:

```json
{"protocol":"acornfox.piworker.v1","type":"open","run_token":"server-generated-base64url","run_id":"run_123","session_id":"session_123","scope":{"kind":"app","application_id":"app_123"}}
```

The worker returns `{"protocol":"acornfox.piworker.v1","type":"ready","run_id":"run_123"}` and the same socket immediately becomes the Pi stdin/stdout stream. Failure responses expose only `busy`, `invalid_handshake`, `scope_mismatch`, or `start_failed`. `piworker.Dial` implements this exchange and preserves any Pi bytes buffered after `ready`.

The run token must be generated and registered by Go. Pi and the model cannot mint an accepted token. The worker passes it only through the Pi child environment for the future trusted extension callback; it never places it in a prompt. Run, session, and scope values are correlation metadata and grant no tool authority. The future Go tool socket must authenticate the token and re-check actor, session, scope, tool name, target, parameters, current fact version, and expiry.

## Configuration credential

The unit loads root-controlled `/etc/acornfox/pi/worker.json` as systemd credential `pi-config`. The model key is a separate `/etc/acornfox/pi/deepseek-api-key` credential; neither file is placed in the setup-token-only `/etc/acornfox/credentials` namespace. The command accepts only `--config %d/pi-config`; a normal user-writable path is rejected. Unknown JSON fields are rejected.

`pi_binary_path` must point into the complete, pinned Pi v0.85.1 package tree verified by packaging. A lone copied executable is insufficient: Pi runtime assets such as package metadata, themes and bundled support resources must remain beside it. The worker neither downloads nor repairs Pi assets.

```json
{
  "schema_version": 1,
  "socket_path": "/run/acornfox-pi/worker.sock",
  "socket_mode": "0660",
  "pi_binary_path": "/opt/acornfox/current/pi/pi",
  "working_directory": "/var/lib/acornfox/pi/work",
  "agent_directory": "/var/lib/acornfox/pi/agent",
  "persist_sessions": true,
  "session_root": "/var/lib/acornfox/pi/sessions",
  "credential_name": "deepseek_api_key",
  "provider": "deepseek",
  "model": "deepseek-v4-flash",
  "thinking": "off",
  "trusted_extensions": ["/opt/acornfox/current/pi/extensions/acornfox-tools.ts"],
  "enabled_tools": ["acornfox_host_metrics", "acornfox_list_apps", "acornfox_app", "acornfox_sources", "acornfox_deliveries", "acornfox_delivery_status", "acornfox_logs", "acornfox_operation_result", "acornfox_public_access", "acornfox_probe"],
  "tool_callback_socket": "/run/acornfox-assistant/tools.sock",
  "handshake_timeout_seconds": 5,
  "run_timeout_seconds": 3600,
  "shutdown_timeout_seconds": 10
}
```

The production configuration persists conversations beneath `session_root`. This directory must be mode 0700 and owned by `acornfox-pi`. A validated server session ID maps only to `<session_root>/<id>.jsonl`; clients cannot supply a path. A mode-0600 sidecar binds that ID to its first `{kind, application_id}` scope, and later scope drift is rejected before Pi starts. Go remains responsible for durable session ownership and scope authorization.

Future tools require all three fields: explicit trusted `.ts` extension paths, exact `acornfox_`-prefixed `enabled_tools`, and a fixed `tool_callback_socket`. The worker always keeps Pi discovery and built-in tools disabled. It contains no database client, Docker socket, host-operation implementation, arbitrary command field, or ambient environment inheritance. The only model credential is read from systemd `LoadCredential` and passed to the Pi child as `DEEPSEEK_API_KEY`.
