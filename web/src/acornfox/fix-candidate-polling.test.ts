import { afterEach, describe, expect, it, vi } from "vitest";
import { pollFixCandidates } from "./fix-candidate-polling";
import type { FixCandidate } from "./fix-candidate-client";

const preparing: FixCandidate = { candidate_id: "candidate-a", application_id: "app-a", base_source_revision_id: "src-a", status: "preparing", created_at: "2030-01-01T00:00:00Z" };
afterEach(() => vi.useRealTimers());
describe("bounded candidate discovery", () => {
  it("discovers candidates during a run, then stops at its read limit", async () => {
    vi.useFakeTimers();
    const read = vi.fn().mockResolvedValueOnce([]).mockResolvedValue([preparing]), receive = vi.fn(), exhausted = vi.fn();
    const stop = pollFixCandidates({ read, receive, fail: vi.fn(), exhausted, running: true, maxReads: 3 });
    await vi.advanceTimersByTimeAsync(90_000);
    expect(read).toHaveBeenCalledTimes(3); expect(receive).toHaveBeenLastCalledWith([preparing]); expect(exhausted).toHaveBeenCalledOnce(); stop();
  });
  it("stops after terminal failure without treating it as publishable", async () => {
    vi.useFakeTimers();
    const read = vi.fn().mockResolvedValueOnce([preparing]).mockResolvedValue([{ ...preparing, status: "failed" }]), receive = vi.fn();
    const stop = pollFixCandidates({ read, receive, fail: vi.fn(), exhausted: vi.fn(), running: false });
    await vi.advanceTimersByTimeAsync(90_000);
    expect(read).toHaveBeenCalledTimes(2); expect(receive).toHaveBeenLastCalledWith([{ ...preparing, status: "failed" }]); stop();
  });
  it("never overlaps requests or delivers old-app responses after unmount", async () => {
    vi.useFakeTimers(); let resolve!: (value: FixCandidate[]) => void;
    const read = vi.fn(() => new Promise<FixCandidate[]>((done) => { resolve = done; })), receive = vi.fn();
    const stop = pollFixCandidates({ read, receive, fail: vi.fn(), exhausted: vi.fn(), running: true });
    await vi.advanceTimersByTimeAsync(90_000); expect(read).toHaveBeenCalledOnce(); stop(); resolve([preparing]);
    await vi.advanceTimersByTimeAsync(90_000); expect(receive).not.toHaveBeenCalled(); expect(read).toHaveBeenCalledOnce();
  });
  it("stops on read failure so stale evidence cannot be refreshed as success", async () => {
    vi.useFakeTimers(); const fail = vi.fn(), read = vi.fn().mockRejectedValue(new Error("offline"));
    const stop = pollFixCandidates({ read, receive: vi.fn(), fail, exhausted: vi.fn(), running: false });
    await vi.advanceTimersByTimeAsync(90_000); expect(fail).toHaveBeenCalledOnce(); expect(read).toHaveBeenCalledOnce(); stop();
  });
});
