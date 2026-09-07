import { afterEach, describe, expect, it, vi } from "vitest";
import { pollAssistantActions } from "./action-polling";

afterEach(() => vi.useRealTimers());
describe("assistant action discovery", () => {
  it("discovers a proposal after two empty reads without depending on existing cards", async () => {
    vi.useFakeTimers();
    const read = vi.fn().mockResolvedValueOnce([]).mockResolvedValueOnce([]).mockResolvedValue(["proposal"]);
    const receive = vi.fn();
    const stop = pollAssistantActions({ read, receive, fail: vi.fn(), maxReads: 12 });
    await vi.advanceTimersByTimeAsync(10_000);
    expect(receive).toHaveBeenLastCalledWith(["proposal"]);
    stop();
  });
  it("starts a fresh bounded window after an idle session and stops even for unchanged pending cards", async () => {
    vi.useFakeTimers();
    const read = vi.fn().mockResolvedValue(["pending"]);
    const first = pollAssistantActions({ read, receive: vi.fn(), fail: vi.fn(), maxReads: 1 });
    await vi.advanceTimersByTimeAsync(65_000);
    expect(read).toHaveBeenCalledTimes(1);
    first();
    const next = pollAssistantActions({ read, receive: vi.fn(), fail: vi.fn(), maxReads: 12 });
    await vi.advanceTimersByTimeAsync(120_000);
    expect(read).toHaveBeenCalledTimes(13);
    next();
  });
  it("does not overlap requests or publish results after switching sessions", async () => {
    vi.useFakeTimers();
    let resolve!: (value: string[]) => void;
    const read = vi.fn(() => new Promise<string[]>((done) => { resolve = done; }));
    const receive = vi.fn();
    const stop = pollAssistantActions({ read, receive, fail: vi.fn(), maxReads: 12 });
    await vi.advanceTimersByTimeAsync(30_000);
    expect(read).toHaveBeenCalledTimes(1);
    stop();
    resolve(["old-session"]);
    await vi.advanceTimersByTimeAsync(30_000);
    expect(receive).not.toHaveBeenCalled();
    expect(read).toHaveBeenCalledTimes(1);
  });
});
