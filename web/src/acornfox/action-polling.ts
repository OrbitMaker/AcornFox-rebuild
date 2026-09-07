// One read at a time. A changed run or action starts a new bounded window.
export function pollAssistantActions<T>(options: {
  read: () => Promise<T>;
  receive: (value: T) => void;
  fail: (error: unknown) => void;
  maxReads: number;
  intervalMs?: number;
}): () => void {
  let stopped = false;
  let reads = 0;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const read = async () => {
    reads += 1;
    try {
      const value = await options.read();
      if (!stopped) options.receive(value);
    } catch (error) {
      if (!stopped) options.fail(error);
    }
    if (!stopped && reads < options.maxReads) {
      timer = setTimeout(() => void read(), options.intervalMs ?? 5_000);
    }
  };
  void read();
  return () => { stopped = true; clearTimeout(timer); };
}
