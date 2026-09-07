# Pi RPC transport

`pirpc` is the pure-Go AcornFox adapter for the Pi v0.85.1 stdio RPC protocol. It is a transport boundary, not an AI session service and not an operating-system sandbox.

The public command surface is intentionally limited to:

- `Prompt`, `Steer`, `FollowUp`
- `Abort`, which always sends `clear_queue` before `abort`
- safe projections from `GetState` and `GetMessages`
- correlated responses to extension UI dialogs

There is no generic RPC call method. In particular the package does not expose Pi's `bash`, `abort_bash`, `switch_session`, `export_html`, model-switching, fork/clone, or arbitrary path commands. Pi tool callbacks to AcornFox belong on a separately authenticated Go/Unix-socket channel and are not implemented here.

`Transport` uses strict LF JSONL framing (with optional CR before LF), never treats U+2028/U+2029 as delimiters, serializes stdin writes, correlates every response by generated request ID, and terminates on malformed/unknown events or uncorrelated responses. The default maximum frame is 1 MiB and all event subscriber queues are bounded. A slow subscriber is detached with `ErrSubscriberSlow`; it cannot block Pi stdout or another subscriber.

A successful prompt response is represented as `Acceptance`. It only means Pi accepted or queued the prompt. `agent_end` and `agent_settled` arrive later as events, and neither proves that an AcornFox operation succeeded. The integrating session service must correlate run, tool invocation, operation/task IDs and fresh persisted response facts.

`Start` owns an optional subprocess. Its binary, working directory, session directory and trusted extension files must pass explicit operator path allowlists. Provider, model and thinking level are required and must each match a separate exact-value allowlist. A DeepSeek Flash smoke config can therefore pin `deepseek`, `deepseek-v4-flash`, and `off` without creating a general CLI argument channel.

The process always supplies `--mode rpc`, the fixed provider/model/thinking flags, `--no-tools`, `--no-extensions`, `--no-skills`, `--no-prompt-templates`, `--no-themes`, `--no-context-files`, and `--no-approve`. Explicit trusted extensions are added with repeated `--extension` flags; Pi v0.85.1 documents that these still load while discovery is disabled. An optional exact `--tools` allowlist may enable only `acornfox_`-prefixed tools and requires a trusted extension; Pi v0.85.1 gives the explicit tool list precedence over `--no-tools`. It adds `--no-session`, one explicit `--session-dir`, or a strictly rooted exact `--session FILE --session-dir DIR` pair and has no arbitrary argument field. The child environment is built only from explicit key/value entries whose keys are also allowlisted; the ambient service environment is not inherited. Raw stderr is discarded to avoid prompt/provider-error logging. `Process.PID()` supports read-only local RSS/CPU observation during smoke tests.

The process wrapper does not switch users, grant or drop privileges, set resource limits, isolate mounts/network, verify package checksums, or claim a root/security boundary. Packaging, a dedicated low-privilege runtime, systemd/container limits, trusted extension loading, Pi built-in-tool disabling and pinned-install verification remain parent integration work.

Event data is normalized into bounded fields. Raw messages, tool arguments/results, extension paths, provider metadata, attachments, images and local file paths are not exposed. `GetMessages` projects only text blocks and basic correlation fields; it rejects `bashExecution` and unknown roles rather than leaking path-bearing data. Returned text is untrusted content and must not be treated as authorization.
