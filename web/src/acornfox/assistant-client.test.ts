import { createAcornFoxAssistantClient } from "./assistant-client";

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
const run = { run_id: "run", session_id: "session", status: "accepted", created_at: "2030-01-01T00:00:00Z", updated_at: "2030-01-01T00:00:00Z" };

describe("AcornFox assistant client", () => {
  beforeEach(() => Object.defineProperty(globalThis, "document", { configurable: true, value: { cookie: "__Host-acornfox_csrf=csrf%20value" } }));

  it("uses the real session routes, keeps a replay key, and protects abort with CSRF", async () => {
    const seen: Array<{ url: string; init?: RequestInit }> = [];
    const api = createAcornFoxAssistantClient(async (input, init) => {
      const url = String(input); seen.push({ url, init });
      if (url.endsWith("/sessions")) return init?.method === "POST" ? json({ session_id: "session", scope: { kind: "host" }, created_at: "2030-01-01T00:00:00Z", updated_at: "2030-01-01T00:00:00Z" }, 201) : json({ sessions: [] });
      if (url.endsWith("/runs")) return json({ run, replay: true });
      if (url.endsWith("/abort")) return json({ aborted: 1 });
      return json({ status: "ok", oldest_cursor: 0, latest_cursor: 0, events: [] });
    });
    await api.sessions();
    await api.createSession({ kind: "host" });
    await expect(api.submitRun("session", "hello", "same-key")).resolves.toMatchObject({ replay: true, run: { runId: "run" } });
    await api.abort("session");
    expect(seen.map((item) => item.url)).toEqual([
      "/api/v1/acornfox/assistant/sessions",
      "/api/v1/acornfox/assistant/sessions",
      "/api/v1/acornfox/assistant/sessions/session/runs",
      "/api/v1/acornfox/assistant/sessions/session/abort",
    ]);
    expect(JSON.parse(String(seen[2]?.init?.body))).toEqual({ message: "hello", idempotency_key: "same-key" });
    expect(seen[3]?.init?.body).toBeUndefined();
    for (const item of seen.slice(1)) expect(new Headers(item.init?.headers).get("X-AcornFox-CSRF")).toBe("csrf value");
  });

  it("decodes split UTF-8 SSE frames and rejects unavailable service without a fake result", async () => {
    const text = `: heartbeat\r\nevent: assistant.delta\r\ndata: ${JSON.stringify({ cursor: 7, run_id: "run", type: "assistant.delta", occurred_at: "2030-01-01T00:00:00Z", text: "你好" })}\r\n\r\nevent: stream.status\r\ndata: {"status":"ok","oldest_cursor":0,"latest_cursor":7}\r\n\r\n`;
    const bytes = new TextEncoder().encode(text);
    const split = new TextEncoder().encode(text.slice(0, text.indexOf("你"))).length + 1;
    const stream = new ReadableStream<Uint8Array>({ start(controller) { controller.enqueue(bytes.slice(0, split)); controller.enqueue(bytes.slice(split)); controller.close(); } });
    let streamHeaders: Headers | undefined;
    const api = createAcornFoxAssistantClient(async (_input, init) => { streamHeaders = new Headers(init?.headers); return new Response(stream, { status: 200, headers: { "Content-Type": "text/event-stream" } }); });
    const events: string[] = [], statuses: string[] = [];
    await api.streamEvents("session", 0, { onEvent: (event) => events.push(event.text ?? ""), onStatus: (status) => statuses.push(status.status) });
    expect(events).toEqual(["你好"]); expect(statuses).toEqual(["ok"]);
    expect(streamHeaders?.get("Last-Event-ID")).toBe("0");
    const unavailable = createAcornFoxAssistantClient(async () => json({ code: "assistant_unavailable", message: "未连接" }, 503));
    await expect(unavailable.sessions()).rejects.toMatchObject({ status: 503, code: "assistant_unavailable" });
  });

  it("accepts the server's empty-session cursor boundary in snapshots and SSE status", async () => {
    const empty = { status: "ok", oldest_cursor: 1, latest_cursor: 0, events: [] };
    const snapshot = createAcornFoxAssistantClient(async () => json(empty));
    await expect(snapshot.events("session", 0)).resolves.toMatchObject({ oldestCursor: 1, latestCursor: 0, events: [] });
    const stream = new ReadableStream<Uint8Array>({ start(controller) { controller.enqueue(new TextEncoder().encode(`event: stream.status\ndata: ${JSON.stringify({ status: "ok", oldest_cursor: 1, latest_cursor: 0 })}\n\n`)); controller.close(); } });
    const sse = createAcornFoxAssistantClient(async () => new Response(stream, { status: 200, headers: { "Content-Type": "text/event-stream" } }));
    const statuses: string[] = [];
    await sse.streamEvents("session", 0, { onEvent: () => undefined, onStatus: (status) => statuses.push(`${status.oldestCursor}/${status.latestCursor}`) });
    expect(statuses).toEqual(["1/0"]);
  });

  it("reads proposals and decides only with an explicit approve field", async () => {
    const proposal = { proposal_id:"p",session_id:"s",run_id:"r",action:"restart",target:{application_id:"a",deployment_id:"d",target_release_id:"rel",target_release_version:1,application_name:"应用"},state:"pending",expires_at:"2030-01-01T00:00:00Z",verification:{state:"pending"},created_at:"2030-01-01T00:00:00Z",updated_at:"2030-01-01T00:00:00Z" };
    const seen: RequestInit[]=[]; const api=createAcornFoxAssistantClient(async (_input,init)=>{seen.push(init??{});return json(init?.method==="POST"?{...proposal,state:"accepted",operation_id:"op"}:{actions:[proposal]},init?.method==="POST"?202:200)});
    await expect(api.actions("s")).resolves.toHaveLength(1); await expect(api.decideAction("s","p",true)).resolves.toMatchObject({state:"accepted"});
    expect(JSON.parse(String(seen[1]?.body))).toEqual({approve:true}); expect(new Headers(seen[1]?.headers).get("X-AcornFox-CSRF")).toBe("csrf value");
  });
});
