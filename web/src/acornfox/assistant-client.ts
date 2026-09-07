import { AcornFoxRequestError } from "./client";

const base = "/api/v1/acornfox/assistant";
const maxStreamBufferBytes = 128 << 10;

type Fetcher = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;
type JsonRecord = Record<string, unknown>;

export type AssistantScope = { kind: "host" } | { kind: "app"; appId: string };
export type AssistantSession = { sessionId: string; scope: AssistantScope; createdAt: string; updatedAt: string };
export type AssistantRun = { runId: string; sessionId: string; status: "accepted" | "running" | "completed" | "failed" | "aborted" | "unknown"; createdAt: string; updatedAt: string };
export type AssistantEvent = { cursor: number; runId?: string; type: "run.accepted" | "run.started" | "assistant.delta" | "assistant.message" | "run.completed" | "run.failed" | "run.aborted" | "run.unknown"; occurredAt: string; text?: string };
export type AssistantSnapshot = { status: "ok" | "slow_consumer" | "expired"; oldestCursor: number; latestCursor: number; events: AssistantEvent[] };
export type AssistantSubmitResult = { run: AssistantRun; replay: boolean };
export type AssistantStreamStatus = Pick<AssistantSnapshot, "status" | "oldestCursor" | "latestCursor">;
export type AssistantProposal = { proposalId: string; sessionId: string; runId: string; action: "restart" | "redeploy"; target: { applicationId: string; deploymentId: string; targetReleaseId: string; targetReleaseVersion: number; applicationName: string }; state: "pending" | "rejected" | "expired" | "executing" | "accepted" | "unknown" | "verified" | "failed"; expiresAt: string; operationId?: string; verification: { state: "pending" | "verified" | "failed"; verdict?: string; observedAt?: string }; createdAt: string; updatedAt: string };

export interface AcornFoxAssistantClient {
  sessions(): Promise<AssistantSession[]>;
  createSession(scope: AssistantScope): Promise<AssistantSession>;
  submitRun(sessionId: string, message: string, idempotencyKey: string): Promise<AssistantSubmitResult>;
  events(sessionId: string, after: number): Promise<AssistantSnapshot>;
  streamEvents(sessionId: string, after: number, handlers: { onEvent: (event: AssistantEvent) => void; onStatus: (status: AssistantStreamStatus) => void; signal?: AbortSignal }): Promise<void>;
  abort(sessionId: string): Promise<{ aborted: number }>;
  actions(sessionId: string): Promise<AssistantProposal[]>;
  decideAction(sessionId: string, proposalId: string, approve: boolean): Promise<AssistantProposal>;
}

function invalid(): never { throw new AcornFoxRequestError(undefined, "invalid_response", "服务返回的数据无法识别。"); }
function record(value: unknown): JsonRecord { return typeof value === "object" && value !== null && !Array.isArray(value) ? value as JsonRecord : invalid(); }
function string(value: unknown): string { return typeof value === "string" ? value : invalid(); }
function optionalString(value: unknown): string | undefined { return value === undefined ? undefined : string(value); }
function number(value: unknown): number { return typeof value === "number" && Number.isFinite(value) ? value : invalid(); }
function integer(value: unknown): number { return Number.isInteger(value) ? number(value) : invalid(); }
function date(value: unknown): string { const result = string(value); return Number.isNaN(Date.parse(result)) ? invalid() : result; }
function exact(value: unknown, required: readonly string[], allowed = required): JsonRecord { const row = record(value); if (!required.every((key) => Object.hasOwn(row, key)) || !Object.keys(row).every((key) => allowed.includes(key))) invalid(); return row; }
function oneOf<T extends string>(value: unknown, values: readonly T[]): T { return typeof value === "string" && values.includes(value as T) ? value as T : invalid(); }
function escapePath(value: string): string { return encodeURIComponent(value); }
function csrf(): string | undefined { if (typeof document === "undefined") return undefined; const cookie = document.cookie.split(";").map((part) => part.trim()).find((part) => part.startsWith("__Host-acornfox_csrf=")); if (!cookie) return undefined; try { return decodeURIComponent(cookie.slice("__Host-acornfox_csrf=".length)); } catch { return undefined; } }
function error(status: number, body: unknown): AcornFoxRequestError { const row = typeof body === "object" && body !== null ? body as JsonRecord : undefined; return new AcornFoxRequestError(status, typeof row?.code === "string" ? row.code : `http_${status}`, typeof row?.message === "string" ? row.message : "请求未完成，请稍后重试。"); }
function scope(value: unknown): AssistantScope { const row = exact(value, ["kind"], ["kind", "app_id"]); const kind = oneOf(row.kind, ["host", "app"]); if (kind === "host") { if (row.app_id !== undefined) invalid(); return { kind }; } return { kind, appId: string(row.app_id) }; }
function session(value: unknown): AssistantSession { const row = exact(value, ["session_id", "scope", "created_at", "updated_at"]); return { sessionId: string(row.session_id), scope: scope(row.scope), createdAt: date(row.created_at), updatedAt: date(row.updated_at) }; }
function run(value: unknown): AssistantRun { const row = exact(value, ["run_id", "session_id", "status", "created_at", "updated_at"]); return { runId: string(row.run_id), sessionId: string(row.session_id), status: oneOf(row.status, ["accepted", "running", "completed", "failed", "aborted", "unknown"]), createdAt: date(row.created_at), updatedAt: date(row.updated_at) }; }
function event(value: unknown): AssistantEvent { const row = exact(value, ["cursor", "type", "occurred_at"], ["cursor", "run_id", "type", "occurred_at", "text"]); const cursor = integer(row.cursor); if (cursor < 1) invalid(); const runId = optionalString(row.run_id); const text = optionalString(row.text); return { cursor, type: oneOf(row.type, ["run.accepted", "run.started", "assistant.delta", "assistant.message", "run.completed", "run.failed", "run.aborted", "run.unknown"]), occurredAt: date(row.occurred_at), ...(runId === undefined ? {} : { runId }), ...(text === undefined ? {} : { text }) }; }
function cursorRange(oldestCursor: number, latestCursor: number, events: readonly AssistantEvent[] = []): void { if (oldestCursor < 0 || latestCursor < 0 || oldestCursor > latestCursor + 1) invalid(); if (events.length && (oldestCursor > latestCursor || events.some((item) => item.cursor < oldestCursor || item.cursor > latestCursor))) invalid(); }
function snapshot(value: unknown): AssistantSnapshot { const row = exact(value, ["status", "oldest_cursor", "latest_cursor", "events"]); if (!Array.isArray(row.events)) invalid(); const oldestCursor = integer(row.oldest_cursor), latestCursor = integer(row.latest_cursor), events = row.events.map(event); cursorRange(oldestCursor, latestCursor, events); return { status: oneOf(row.status, ["ok", "slow_consumer", "expired"]), oldestCursor, latestCursor, events }; }
function submit(value: unknown): AssistantSubmitResult { const row = exact(value, ["run", "replay"]); if (typeof row.replay !== "boolean") invalid(); return { run: run(row.run), replay: row.replay }; }
function streamStatus(value: unknown): AssistantStreamStatus { const row = exact(value, ["status", "oldest_cursor", "latest_cursor"]); const oldestCursor = integer(row.oldest_cursor), latestCursor = integer(row.latest_cursor); cursorRange(oldestCursor, latestCursor); return { status: oneOf(row.status, ["ok", "slow_consumer", "expired"]), oldestCursor, latestCursor }; }
function proposal(value: unknown): AssistantProposal { const row = exact(value,["proposal_id","session_id","run_id","action","target","state","expires_at","verification","created_at","updated_at"],["proposal_id","session_id","run_id","action","target","state","expires_at","operation_id","verification","created_at","updated_at"]); const target=exact(row.target,["application_id","deployment_id","target_release_id","target_release_version","application_name"]), verification=exact(row.verification,["state"],["state","verdict","observed_at"]); const operationId=optionalString(row.operation_id), verdict=optionalString(verification.verdict), observedAt=verification.observed_at===undefined?undefined:date(verification.observed_at); return { proposalId:string(row.proposal_id),sessionId:string(row.session_id),runId:string(row.run_id),action:oneOf(row.action,["restart","redeploy"]),target:{applicationId:string(target.application_id),deploymentId:string(target.deployment_id),targetReleaseId:string(target.target_release_id),targetReleaseVersion:integer(target.target_release_version),applicationName:string(target.application_name)},state:oneOf(row.state,["pending","rejected","expired","executing","accepted","unknown","verified","failed"]),expiresAt:date(row.expires_at),...(operationId===undefined?{}:{operationId}),verification:{state:oneOf(verification.state,["pending","verified","failed"]),...(verdict===undefined?{}:{verdict}),...(observedAt===undefined?{}:{observedAt})},createdAt:date(row.created_at),updatedAt:date(row.updated_at)}; }

export function newAssistantIdempotencyKey(): string { if (typeof crypto === "undefined" || typeof crypto.getRandomValues !== "function") invalid(); if (typeof crypto.randomUUID === "function") return crypto.randomUUID(); return Array.from(crypto.getRandomValues(new Uint8Array(16)), (byte) => byte.toString(16).padStart(2, "0")).join(""); }

export function createAcornFoxAssistantClient(fetcher: Fetcher = fetch): AcornFoxAssistantClient {
  async function request<T>(path: string, parse: (value: unknown) => T, init: RequestInit = {}, statuses: readonly number[] = [200]): Promise<T> {
    const headers = new Headers(init.headers); if (init.body !== undefined) headers.set("Content-Type", "application/json");
    if (init.method && init.method !== "GET") { const token = csrf(); if (!token) throw new AcornFoxRequestError(401, "csrf_missing", "登录信息已失效，请重新登录。"); headers.set("X-AcornFox-CSRF", token); }
    let response: Response; try { response = await fetcher(`${base}${path}`, { ...init, headers, credentials: "include", redirect: "error" }); } catch { throw new AcornFoxRequestError(undefined, "network_error", "请求未完成，请检查连接后重试。"); }
    if (!statuses.includes(response.status)) { let body: unknown; try { body = await response.json(); } catch { /* opaque error */ } throw error(response.status, body); }
    try { return parse(await response.json()); } catch (cause) { if (cause instanceof AcornFoxRequestError) throw cause; return invalid(); }
  }
  return {
    sessions: () => request("/sessions", (value) => { const row = exact(value, ["sessions"]); return Array.isArray(row.sessions) ? row.sessions.map(session) : invalid(); }),
    createSession: (value) => request("/sessions", session, { method: "POST", body: JSON.stringify({ scope: value.kind === "host" ? { kind: "host" } : { kind: "app", app_id: value.appId } }) }, [201]),
    submitRun: (sessionId, message, idempotencyKey) => { if (!message.trim() || !idempotencyKey) throw new AcornFoxRequestError(422, "invalid_input", "消息和重试标识不能为空。"); return request(`/sessions/${escapePath(sessionId)}/runs`, submit, { method: "POST", body: JSON.stringify({ message: message.trim(), idempotency_key: idempotencyKey }) }, [200, 202]); },
    events: (sessionId, after) => { if (!Number.isInteger(after) || after < 0) throw new AcornFoxRequestError(422, "invalid_input", "事件游标无效。"); return request(`/sessions/${escapePath(sessionId)}/events?after=${after}`, snapshot, {}, [200, 409]); },
    streamEvents: async (sessionId, after, handlers) => {
      if (!Number.isInteger(after) || after < 0) throw new AcornFoxRequestError(422, "invalid_input", "事件游标无效。");
      let response: Response; try { response = await fetcher(`${base}/sessions/${escapePath(sessionId)}/events?after=${after}`, { headers: { Accept: "text/event-stream", "Last-Event-ID": String(after) }, credentials: "include", redirect: "error", signal: handlers.signal }); } catch { if (handlers.signal?.aborted) return; throw new AcornFoxRequestError(undefined, "network_error", "事件流已断开。"); }
      if (response.status === 409) { handlers.onStatus(streamStatus(await response.json())); return; }
      if (response.status !== 200 || !response.body) { let body: unknown; try { body = await response.json(); } catch { /* opaque error */ } throw error(response.status, body); }
      if (!response.headers.get("Content-Type")?.toLowerCase().includes("text/event-stream")) invalid();
      const reader = response.body.getReader(), decoder = new TextDecoder(); let buffer = "", frame = "";
      const consume = (raw: string) => { const lines = raw.replace(/\r/g, "").split("\n"); let type = "", data = ""; for (const line of lines) { if (line.startsWith("event:")) type = line.slice(6).trim(); if (line.startsWith("data:")) data += line.slice(5).trim(); } if (!data) return; const parsed: unknown = JSON.parse(data); if (type === "stream.status") handlers.onStatus(streamStatus(parsed)); else handlers.onEvent(event(parsed)); };
      try { for (;;) { const next = await reader.read(); if (next.done) break; buffer += decoder.decode(next.value, { stream: true }); if (buffer.length > maxStreamBufferBytes) throw new AcornFoxRequestError(undefined, "stream_buffer_exceeded", "事件流数据过大，已停止读取。"); let boundary: RegExpMatchArray | null; while ((boundary = buffer.match(/\r?\n\r?\n/)) !== null) { const index = boundary.index ?? 0; frame += buffer.slice(0, index); buffer = buffer.slice(index + boundary[0].length); if (frame.length > maxStreamBufferBytes) throw new AcornFoxRequestError(undefined, "stream_buffer_exceeded", "事件流数据过大，已停止读取。"); consume(frame); frame = ""; } } } finally { reader.releaseLock(); }
    },
    abort: (sessionId) => request(`/sessions/${escapePath(sessionId)}/abort`, (value) => { const row = exact(value, ["aborted"]); const aborted = integer(row.aborted); return aborted >= 0 ? { aborted } : invalid(); }, { method: "POST" }),
    actions: (sessionId) => request(`/sessions/${escapePath(sessionId)}/actions`, (value) => { const row=exact(value,["actions"]); return Array.isArray(row.actions)?row.actions.map(proposal):invalid(); }),
    decideAction: (sessionId, proposalId, approve) => request(`/sessions/${escapePath(sessionId)}/actions/${escapePath(proposalId)}/decision`, proposal, { method:"POST", body:JSON.stringify({approve}) }, [200,202]),
  };
}
