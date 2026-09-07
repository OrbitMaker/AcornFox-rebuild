import type { AssistantEvent, AssistantSnapshot, AssistantStreamStatus } from "./assistant-client";

type RecoveryOptions = {
  cursor: () => number;
  read: (after: number, signal: AbortSignal) => Promise<AssistantSnapshot>;
  connect: (after: number, handlers: { signal: AbortSignal; onEvent: (event: AssistantEvent) => void; onStatus: (status: AssistantStreamStatus) => void }) => Promise<void>;
  receive: (events: readonly AssistantEvent[], resetAfter?: number) => void;
  ready: () => void;
  retrying: (attempt: number) => void;
  exhausted: () => void;
  // Wait for a cancelled predecessor to settle before starting a replacement.
  // Its fetch receives the abort signal and cannot deliver late facts.
  waitFor?: Promise<void>;
  maxRetries?: number;
  baseDelayMs?: number;
};

function delay(milliseconds: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve) => {
    if (signal.aborted) { resolve(); return; }
    const done = () => { clearTimeout(timer); signal.removeEventListener("abort", done); resolve(); };
    const timer = setTimeout(done, milliseconds);
    signal.addEventListener("abort", done, { once: true });
  });
}

export function recoverAssistantStream(options: RecoveryOptions): { stop: () => void; done: Promise<void> } {
  const controller = new AbortController(), signal = controller.signal;
  const readSnapshot = async (after: number): Promise<AssistantSnapshot> => {
    const request = new AbortController();
    const cancel = () => request.abort();
    if (signal.aborted) throw new Error("assistant recovery cancelled");
    signal.addEventListener("abort", cancel, { once: true });
    const timer = setTimeout(cancel, 10_000);
    try {
      const result = await options.read(after, request.signal);
      if (request.signal.aborted) throw new Error("assistant snapshot cancelled or timed out");
      return result;
    } finally { clearTimeout(timer); signal.removeEventListener("abort", cancel); }
  };
  const readPersisted = async () => {
    let snapshot = await readSnapshot(options.cursor());
    if (signal.aborted) return;
    let resetAfter: number | undefined;
    if (snapshot.status === "expired") {
      resetAfter = Math.max(0, snapshot.oldestCursor - 1);
      snapshot = await readSnapshot(resetAfter);
      if (signal.aborted) return;
      if (snapshot.status === "expired") throw new Error("assistant replay window moved again");
    }
    options.receive(snapshot.events, resetAfter);
    options.ready();
  };
  const connect = async () => {
    const connection = new AbortController();
    const cancel = () => connection.abort();
    signal.addEventListener("abort", cancel, { once: true });
    try {
      await options.connect(options.cursor(), {
        signal: connection.signal,
        onEvent: (event) => { if (!signal.aborted && !connection.signal.aborted) options.receive([event]); },
        onStatus: (status) => {
          if (signal.aborted || connection.signal.aborted) return;
          // End this connection before reading a snapshot. Recovery remains
          // serial even when an expiry status arrives before the stream ends.
          if (status.status === "expired" || status.status === "slow_consumer") connection.abort();
        },
      });
    } finally { signal.removeEventListener("abort", cancel); }
  };
  const done = (async () => {
    await options.waitFor;
    const maximum = options.maxRetries ?? 5;
    for (let attempt = 0; attempt <= maximum; attempt += 1) {
      if (signal.aborted) return;
      if (attempt > 0) {
        options.retrying(attempt);
        await delay(Math.min((options.baseDelayMs ?? 1_000) * 2 ** (attempt - 1), 30_000), signal);
        if (signal.aborted) return;
      }
      try {
        await readPersisted();
        if (signal.aborted) return;
        await connect();
      } catch {
        // Both a normal lifetime EOF and transport failure resume from the
        // durable event endpoint on the next bounded attempt. Neither writes.
      }
    }
    if (!signal.aborted) options.exhausted();
  })();
  return { stop: () => controller.abort(), done };
}
