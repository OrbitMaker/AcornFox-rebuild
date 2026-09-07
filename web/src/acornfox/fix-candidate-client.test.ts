import { candidatePublishKey, createFixCandidateClient, decodeFixCandidate } from "./fix-candidate-client";

import { candidateFixture } from "./fix-candidate.fixture";

const json = (value: unknown, status = 200) => new Response(JSON.stringify(value), { status, headers: { "Content-Type": "application/json" } });

describe("fix candidate transport and authority", () => {
  beforeEach(() => Object.defineProperty(globalThis, "document", { configurable: true, value: { cookie: "__Host-acornfox_csrf=csrf%20value" } }));
  it("recognizes preparing and failed without inventing completed evidence", async () => {
    const minimum = { candidate_id: candidateFixture.candidate_id, application_id: "app-1", base_source_revision_id: "src-base", created_at: candidateFixture.created_at };
    for (const status of ["preparing", "failed"]) {
      const api = createFixCandidateClient(async () => json({ items: [{ ...minimum, status }] }));
      await expect(api.list("app-1")).resolves.toEqual([{ ...minimum, status }]);
    }
    expect(() => decodeFixCandidate({ ...minimum, status: "validated" }, "app-1")).toThrow();
  });
  it("rejects foreign app, wrong candidate, failed cleanup and image substitution", async () => {
    expect(() => decodeFixCandidate(candidateFixture, "another-app")).toThrow();
    expect(() => decodeFixCandidate({ ...candidateFixture, runtime: { ...candidateFixture.runtime, cleanup_confirmed: false } }, "app-1")).toThrow();
    expect(() => decodeFixCandidate({ ...candidateFixture, runtime: { ...candidateFixture.runtime, image: { ...candidateFixture.validated_image, repository: "other/repo" } } }, "app-1")).toThrow();
    const api = createFixCandidateClient(async () => json(candidateFixture));
    await expect(api.get("app-1", `candidate_${"b".repeat(32)}`)).rejects.toMatchObject({ code: "invalid_response" });
  });
  it("rejects duplicate list rows, unknown status, and incomplete matched identity", async () => {
    const api = createFixCandidateClient(async () => json({ items: [candidateFixture, candidateFixture] }));
    await expect(api.list("app-1")).rejects.toMatchObject({ code: "invalid_response" });
    expect(() => decodeFixCandidate({ ...candidateFixture, status: "complete" }, "app-1")).toThrow();
    expect(() => decodeFixCandidate({ ...candidateFixture, status: "source_matched" }, "app-1")).toThrow();
  });
  it("matches the exact selected source and protects both writes with CSRF", async () => {
    const seen: RequestInit[] = [];
    const api = createFixCandidateClient(async (_url, init) => { seen.push(init ?? {}); return json({ ...candidateFixture, status: "source_matched", matched_source_revision_id: "src-fixed", matched_commit: "3".repeat(40) }); });
    await expect(api.match("app-1", candidateFixture.candidate_id, "src-fixed")).resolves.toMatchObject({ matched_source_revision_id: "src-fixed" });
    expect(JSON.parse(String(seen[0]?.body))).toEqual({ source_revision_id: "src-fixed" });
    expect(new Headers(seen[0]?.headers).get("X-AcornFox-CSRF")).toBe("csrf value");
    expect(seen[0]).toMatchObject({ credentials: "include", redirect: "error" });
    await expect(api.match("app-1", candidateFixture.candidate_id, "src-other")).rejects.toMatchObject({ code: "invalid_response" });
  });
  it("retries an unknown publication with exactly the same key and empty body across client instances", async () => {
    const seen: RequestInit[] = [];
    const fetcher = async (_url: RequestInfo | URL, init?: RequestInit) => { seen.push(init ?? {}); if (seen.length === 1) throw new Error("response lost after acceptance"); return json({ deployment_id: "dep-1", operation_id: "op-1", task_id: "task-1", status: "accepted" }, 202); };
    await expect(createFixCandidateClient(fetcher).publish("app-1", candidateFixture.candidate_id, candidatePublishKey("app-1", candidateFixture.candidate_id))).rejects.toMatchObject({ code: "network_error" });
    await expect(createFixCandidateClient(fetcher).publish("app-1", candidateFixture.candidate_id, candidatePublishKey("app-1", candidateFixture.candidate_id))).resolves.toMatchObject({ deployment_id: "dep-1", status: "accepted" });
    expect(seen).toHaveLength(2);
    for (const call of seen) { expect(new Headers(call.headers).get("Idempotency-Key")).toBe(candidatePublishKey("app-1", candidateFixture.candidate_id)); expect(new Headers(call.headers).get("X-AcornFox-CSRF")).toBe("csrf value"); expect(call.body).toBeUndefined(); }
    expect(candidatePublishKey("app-other", candidateFixture.candidate_id)).not.toBe(candidatePublishKey("app-1", candidateFixture.candidate_id));
  });
});
