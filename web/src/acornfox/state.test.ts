import { ActionScope, LatestRequest, refetchAfterAccepted } from "./state";

describe("accepted command refresh", () => {
  it("performs one explicit read and never schedules another read", async () => {
    const refresh = vi.fn(async () => undefined);
    await refetchAfterAccepted(refresh);
    expect(refresh).toHaveBeenCalledTimes(1);
  });
});

describe("action scope", () => {
  it("admits one action, requires a current completion, and ignores logout invalidation", () => {
    const scope = new ActionScope();
    const first = scope.begin();
    expect(first).toBeDefined();
    expect(scope.begin()).toBeUndefined();
    expect(first?.current()).toBe(true);
    scope.invalidate();
    expect(first?.current()).toBe(false);
    expect(first?.finish()).toBe(false);
    expect(scope.begin()).toBeDefined();
  });

  it("does not begin a post-action read after a deferred scope switch", async () => {
    let resolve!: () => void;
    const completion = new Promise<void>((done) => {
      resolve = done;
    });
    const scope = new ActionScope();
    const ticket = scope.begin();
    const refresh = vi.fn(async () => undefined);
    const task = completion.then(async () => {
      if (ticket?.current()) await refetchAfterAccepted(refresh);
      ticket?.finish();
    });
    scope.invalidate();
    resolve();
    await task;
    expect(refresh).not.toHaveBeenCalled();
  });
});

describe("latest request guard", () => {
  it("prevents an older deferred response from replacing a newer scope", () => {
    const guard = new LatestRequest();
    const stale = guard.begin();
    const current = guard.begin();
    expect(stale()).toBe(false);
    expect(current()).toBe(true);
    guard.invalidate();
    expect(current()).toBe(false);
  });

  it("does not let a deferred A response overwrite B", async () => {
    let resolveA!: () => void;
    let resolveB!: () => void;
    const a = new Promise<void>((resolve) => {
      resolveA = resolve;
    });
    const b = new Promise<void>((resolve) => {
      resolveB = resolve;
    });
    const guard = new LatestRequest();
    const writes: string[] = [];
    const aCurrent = guard.begin();
    const aTask = a.then(() => {
      if (aCurrent()) writes.push("A");
    });
    const bCurrent = guard.begin();
    const bTask = b.then(() => {
      if (bCurrent()) writes.push("B");
    });
    resolveB();
    await bTask;
    resolveA();
    await aTask;
    expect(writes).toEqual(["B"]);
  });
});
