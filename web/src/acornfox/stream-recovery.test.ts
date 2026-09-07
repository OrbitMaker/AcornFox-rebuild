import { afterEach, describe, expect, it, vi } from "vitest";
import { applyAssistantEvents } from "./Assistant";
import { createAcornFoxAssistantClient, type AssistantEvent, type AssistantSnapshot } from "./assistant-client";
import { recoverAssistantStream } from "./stream-recovery";

afterEach(() => vi.useRealTimers());
const event = (cursor: number, type: AssistantEvent["type"]): AssistantEvent => ({ cursor, type, runId: "run-1", occurredAt: "2030-01-01T00:00:00Z" });
const snapshot = (events: AssistantEvent[], oldestCursor = 1): AssistantSnapshot => ({ status: "ok", oldestCursor, latestCursor: events.at(-1)?.cursor ?? 0, events });
const waitingStream = (_after: number, handlers: { signal: AbortSignal }) => new Promise<void>((resolve) => { if (handlers.signal.aborted) resolve(); else handlers.signal.addEventListener("abort", () => resolve(), { once: true }); });
function facts() {
  let current = { cursor: 0, incomplete: false, messages: [] as Array<{ id: string; role: "user" | "assistant" | "system"; text: string }>, runStates: {} as Record<string, string> };
  return {
    cursor: () => current.cursor,
    state: () => current,
    receive: (events: readonly AssistantEvent[], resetAfter?: number) => { current = applyAssistantEvents(resetAfter === undefined ? current : { ...current, cursor: resetAfter, incomplete: true }, events); },
  };
}

describe("assistant stream recovery", () => {
  it.each(["clean EOF", "network error"])("recovers %s and reads the durable unknown event before reconnecting", async (ending) => {
    vi.useFakeTimers();
    const state = facts(), read = vi.fn().mockResolvedValueOnce(snapshot([event(1, "run.started")])).mockResolvedValue(snapshot([event(3, "run.unknown")]));
    const connect = vi.fn().mockImplementationOnce(async (_after, handlers) => { handlers.onEvent(event(2, "assistant.delta")); if (ending === "network error") throw new Error("connection reset"); }).mockImplementation(waitingStream);
    const ready = vi.fn(), retrying = vi.fn();
    const recovery = recoverAssistantStream({ ...state, read, connect, ready, retrying, exhausted: vi.fn() });
    await vi.advanceTimersByTimeAsync(1_000);
    expect(read.mock.calls.map((call) => call[0])).toEqual([0, 2]);
    expect(connect.mock.calls.map((call) => call[0])).toEqual([1, 3]);
    expect(state.state().runStates["run-1"]).toBe("unknown");
    expect(state.state().messages.at(-1)?.text).toBe("本轮结果未知。");
    expect(retrying).toHaveBeenCalledWith(1); expect(ready).toHaveBeenCalledTimes(2);
    recovery.stop(); await recovery.done;
  });

  it("recovers from 503 without keeping the connection disabled and bounds repeated failures", async () => {
    vi.useFakeTimers(); const state = facts(), ready = vi.fn(), exhausted = vi.fn();
    const read = vi.fn().mockRejectedValueOnce({ status: 503 }).mockResolvedValue(snapshot([event(1, "run.completed")]));
    const recovery = recoverAssistantStream({ ...state, read, connect: vi.fn(waitingStream), ready, retrying: vi.fn(), exhausted });
    await vi.advanceTimersByTimeAsync(1_000); expect(ready).toHaveBeenCalledOnce(); expect(state.state().runStates["run-1"]).toBe("completed"); expect(exhausted).not.toHaveBeenCalled(); recovery.stop(); await recovery.done;

    const failedRead = vi.fn().mockRejectedValue({ status: 503 }), retrying = vi.fn();
    const failing = recoverAssistantStream({ ...facts(), read: failedRead, connect: vi.fn(), ready: vi.fn(), retrying, exhausted });
    await vi.advanceTimersByTimeAsync(60_000); await failing.done;
    expect(failedRead).toHaveBeenCalledTimes(6); expect(retrying.mock.calls.map((call) => call[0])).toEqual([1, 2, 3, 4, 5]); expect(exhausted).toHaveBeenCalledOnce();
    await vi.advanceTimersByTimeAsync(300_000); expect(failedRead).toHaveBeenCalledTimes(6);
  });

  it("recovers expired snapshot and stream cursors serially and marks the transcript incomplete", async () => {
    vi.useFakeTimers(); const state = facts();
    const read = vi.fn()
      .mockResolvedValueOnce({ status: "expired", oldestCursor: 5, latestCursor: 6, events: [] })
      .mockResolvedValueOnce(snapshot([event(5, "run.started"), event(6, "run.unknown")], 5))
      .mockResolvedValueOnce({ status: "expired", oldestCursor: 8, latestCursor: 8, events: [] })
      .mockResolvedValueOnce(snapshot([event(8, "run.completed")], 8));
    const connect = vi.fn().mockImplementationOnce(async (_after, handlers) => {
      handlers.onStatus({ status: "expired", oldestCursor: 8, latestCursor: 8 });
      expect(handlers.signal.aborted).toBe(true);
      // A cancelled connection cannot push late stale events.
      handlers.onEvent(event(99, "run.started"));
    }).mockImplementation(waitingStream);
    const recovery = recoverAssistantStream({ ...state, read, connect, ready: vi.fn(), retrying: vi.fn(), exhausted: vi.fn() });
    await vi.advanceTimersByTimeAsync(1_000);
    expect(read.mock.calls.map((call) => call[0])).toEqual([0, 4, 6, 7]); expect(connect.mock.calls.map((call) => call[0])).toEqual([6, 8]);
    expect(state.state()).toMatchObject({ cursor: 8, incomplete: true, runStates: { "run-1": "completed" } }); recovery.stop(); await recovery.done;
  });

  it("waits for an aborted snapshot to settle before replacing the stream and discards its late response", async () => {
    vi.useFakeTimers(); let finish!: (value: AssistantSnapshot) => void;
    let oldSignal: AbortSignal | undefined;
    const oldReceive = vi.fn(), oldRead = vi.fn((_after: number, signal: AbortSignal) => { oldSignal = signal; return new Promise<AssistantSnapshot>((resolve) => { finish = resolve; }); });
    const old = recoverAssistantStream({ cursor: () => 0, read: oldRead, connect: vi.fn(waitingStream), receive: oldReceive, ready: vi.fn(), retrying: vi.fn(), exhausted: vi.fn() });
    await vi.advanceTimersByTimeAsync(0); old.stop(); expect(oldSignal?.aborted).toBe(true);
    const newRead = vi.fn().mockResolvedValue(snapshot([event(1, "run.completed")]));
    const replacement = recoverAssistantStream({ ...facts(), waitFor: old.done, read: newRead, connect: vi.fn(waitingStream), ready: vi.fn(), retrying: vi.fn(), exhausted: vi.fn() });
    await vi.advanceTimersByTimeAsync(30_000); expect(newRead).not.toHaveBeenCalled();
    finish(snapshot([event(1, "run.started")])); await vi.advanceTimersByTimeAsync(0);
    expect(oldReceive).not.toHaveBeenCalled(); expect(newRead).toHaveBeenCalledOnce(); replacement.stop(); await replacement.done;
  });

  it("aborts hung snapshot fetches after ten seconds and exhausts the finite retry budget", async () => {
    vi.useFakeTimers(); const state = facts(), ready = vi.fn(), exhausted = vi.fn(), receive = vi.fn();
    let active = 0, maximumActive = 0, requests = 0, aborted = 0;
    const client = createAcornFoxAssistantClient(async (_url, init) => {
      active += 1; requests += 1; maximumActive = Math.max(maximumActive, active);
      return new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener("abort", () => { active -= 1; aborted += 1; reject(new Error("snapshot fetch aborted")); }, { once: true });
      });
    });
    const connect = vi.fn();
    const recovery = recoverAssistantStream({ ...state, receive, read: (after, signal) => client.events("session", after, signal), connect, ready, retrying: vi.fn(), exhausted });
    await vi.advanceTimersByTimeAsync(9_999); expect(requests).toBe(1); expect(aborted).toBe(0);
    await vi.advanceTimersByTimeAsync(1); expect(aborted).toBe(1); expect(requests).toBe(1);
    await vi.advanceTimersByTimeAsync(81_000); await recovery.done;
    expect(requests).toBe(6); expect(aborted).toBe(6); expect(maximumActive).toBe(1); expect(active).toBe(0);
    expect(ready).not.toHaveBeenCalled(); expect(receive).not.toHaveBeenCalled(); expect(connect).not.toHaveBeenCalled(); expect(exhausted).toHaveBeenCalledOnce();
    await vi.advanceTimersByTimeAsync(60_000); expect(requests).toBe(6); expect(vi.getTimerCount()).toBe(0);
  });

  it("immediately aborts a hung read when switching sessions, then starts the replacement without overlap", async () => {
    vi.useFakeTimers(); let active = 0, aborted = false;
    const old = recoverAssistantStream({ ...facts(), read: (_after, signal) => { active += 1; return new Promise<AssistantSnapshot>((_resolve, reject) => { signal.addEventListener("abort", () => { aborted = true; active -= 1; reject(new Error("aborted")); }, { once: true }); }); }, connect: vi.fn(), ready: vi.fn(), retrying: vi.fn(), exhausted: vi.fn() });
    await vi.advanceTimersByTimeAsync(0); expect(active).toBe(1); old.stop(); expect(aborted).toBe(true);
    const read = vi.fn(async () => { expect(active).toBe(0); return snapshot([event(1, "run.unknown")]); });
    const replacement = recoverAssistantStream({ ...facts(), waitFor: old.done, read, connect: waitingStream, ready: vi.fn(), retrying: vi.fn(), exhausted: vi.fn() });
    await vi.advanceTimersByTimeAsync(0); expect(read).toHaveBeenCalledOnce(); replacement.stop(); await replacement.done; expect(vi.getTimerCount()).toBe(0);
  });

  it("cancels pending backoff on unmount and does not resurrect a stopped controller", async () => {
    vi.useFakeTimers(); const read = vi.fn().mockRejectedValue(new Error("offline")), exhausted = vi.fn();
    const recovery = recoverAssistantStream({ ...facts(), read, connect: vi.fn(), ready: vi.fn(), retrying: vi.fn(), exhausted });
    await vi.advanceTimersByTimeAsync(0); recovery.stop(); await recovery.done; await vi.advanceTimersByTimeAsync(60_000);
    expect(read).toHaveBeenCalledOnce(); expect(exhausted).not.toHaveBeenCalled();
  });

  it("resumes through the real SSE decoder without submitting runs or mutations", async () => {
    vi.useFakeTimers(); const state = facts(), requests: Array<{ after: string | null; method: string; streaming: boolean }> = [];
    let streams = 0, reads = 0;
    const client = createAcornFoxAssistantClient(async (url, init) => {
      const streaming = new Headers(init?.headers).get("Accept") === "text/event-stream";
      requests.push({ after: new URL(String(url), "https://test.invalid").searchParams.get("after"), method: init?.method ?? "GET", streaming });
      if (!streaming) {
        reads += 1;
        const current = reads === 1 ? { cursor: 1, type: "run.started" } : { cursor: 2, type: "run.unknown" };
        return new Response(JSON.stringify({ status: "ok", oldest_cursor: 1, latest_cursor: current.cursor, events: [{ ...current, run_id: "run-1", occurred_at: "2030-01-01T00:00:00Z" }] }), { headers: { "Content-Type": "application/json" } });
      }
      streams += 1;
      const body = new ReadableStream<Uint8Array>({ start(controller) { if (streams === 1) controller.close(); else init?.signal?.addEventListener("abort", () => controller.close(), { once: true }); } });
      return new Response(body, { headers: { "Content-Type": "text/event-stream" } });
    });
    const recovery = recoverAssistantStream({ ...state, read: (after, signal) => client.events("session", after, signal), connect: (after, handlers) => client.streamEvents("session", after, handlers), ready: vi.fn(), retrying: vi.fn(), exhausted: vi.fn() });
    await vi.advanceTimersByTimeAsync(1_000);
    expect(requests).toEqual([{ after: "0", method: "GET", streaming: false }, { after: "1", method: "GET", streaming: true }, { after: "1", method: "GET", streaming: false }, { after: "2", method: "GET", streaming: true }]);
    expect(state.state().runStates["run-1"]).toBe("unknown"); recovery.stop(); await recovery.done;
  });
});
