import type { FixCandidate } from "./fix-candidate-client";

export function pollFixCandidates(options: {
  read: () => Promise<FixCandidate[]>;
  receive: (items: FixCandidate[]) => void;
  fail: (error: unknown) => void;
  exhausted: () => void;
  running: boolean;
  maxReads?: number;
  intervalMs?: number;
}): () => void {
  let stopped = false, reads = 0;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const tick = async () => {
    reads += 1;
    try {
      const items = await options.read();
      if (stopped) return;
      options.receive(items);
      if (!options.running && !items.some((item) => item.status === "preparing")) return;
      if (reads >= (options.maxReads ?? 61)) { options.exhausted(); return; }
      timer = setTimeout(() => void tick(), options.intervalMs ?? 5_000);
    } catch (error) { if (!stopped) options.fail(error); }
  };
  void tick();
  return () => { stopped = true; clearTimeout(timer); };
}
