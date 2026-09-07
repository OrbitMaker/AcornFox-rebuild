import { createAcornFoxIntegrationClient } from "./integration-client";

type Seen = { url: string; init?: RequestInit };
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });

describe("AcornFox integration client", () => {
  beforeEach(() => {
    Object.defineProperty(globalThis, "document", { configurable: true, value: { cookie: "__Host-acornfox_csrf=csrf%20value" } });
  });

  it("keeps added capability routes separate and preserves optional unknown metrics", async () => {
    const seen: Seen[] = [];
    const api = createAcornFoxIntegrationClient(async (input, init) => {
      const url = String(input); seen.push({ url, init });
      if (url.endsWith("/setup") && init?.method === "POST") return json({ initialized: true }, 201);
      if (url.endsWith("/setup")) return json({ state: "uninitialized" });
      if (url.endsWith("/host/metrics")) return json({ schema_version: 1, availability: "warming_up", stale_after_seconds: 15, cpu: { logical_cores: 4 } });
      if (url.endsWith("/sources") && init?.method === "POST") return json({ source_revision_id: "s-next", status: "imported" }, 201);
      if (url.endsWith("/metadata")) return json({ source_revision_id: "s", availability: "unavailable" });
      if (url.includes("/operations/")) return json({ operation_id: "o", operation_type: "probe", status: "verified", task_id: "t", deployment_id: "d", accepted_at: "2030-01-01T00:00:00Z", updated_at: "2030-01-01T00:00:01Z", evidence: { kind: "response_observation", verdict: "unhealthy", observed_at: "2030-01-01T00:00:01Z", http_status: 500 } });
      return json({ deployment_id: "d", availability: "available", source_revision_id: "s", commit: "abc", ref: "main" });
    });
    await expect(api.setupState()).resolves.toBe("uninitialized");
    await expect(api.setup({ setupToken: "single-use", password: "not-a-real-password" })).resolves.toBeUndefined();
    await expect(api.hostMetrics()).resolves.toMatchObject({ availability: "warming_up", cpu: { logicalCores: 4 } });
    await expect(api.sourceMetadata("app id", "s id")).resolves.toEqual({ sourceRevisionId: "s", availability: "unavailable" });
    await expect(api.sourceUpdate("app id", { baseSourceRevisionId: "s id", ref: "main" }, "same-request")).resolves.toEqual({ sourceRevisionId: "s-next", status: "imported" });
    await expect(api.deploymentSource("app id", "d id")).resolves.toMatchObject({ deploymentId: "d", commit: "abc" });
    await expect(api.operationResult("app id", "o id")).resolves.toMatchObject({ operationId: "o", status: "verified", evidence: { verdict: "unhealthy", httpStatus: 500 } });
    expect(seen.map((item) => item.url)).toEqual([
      "/api/v1/acornfox/setup",
      "/api/v1/acornfox/setup",
      "/api/v1/acornfox/host/metrics",
      "/api/v1/acornfox/apps/app%20id/sources/s%20id/metadata",
      "/api/v1/acornfox/apps/app%20id/sources",
      "/api/v1/acornfox/apps/app%20id/deliveries/d%20id/source",
      "/api/v1/acornfox/apps/app%20id/operations/o%20id",
    ]);
    expect(new Headers(seen[1]?.init?.headers).get("X-AcornFox-CSRF")).toBe("csrf value");
    expect(new Headers(seen[1]?.init?.headers).get("Idempotency-Key")).toBeNull();
    expect(new Headers(seen[4]?.init?.headers).get("Idempotency-Key")).toBe("same-request");
    expect(JSON.parse(String(seen[4]?.init?.body))).toEqual({ base_source_revision_id: "s id", ref: "main" });
    expect(seen[5]?.init?.method).toBeUndefined();
    expect(new Headers(seen[5]?.init?.headers).get("X-AcornFox-CSRF")).toBeNull();
  });

  it("does not turn malformed or unavailable added capabilities into success", async () => {
    const malformed = createAcornFoxIntegrationClient(async () => json({ schema_version: 1, availability: "available", stale_after_seconds: 15, leaked: true }));
    await expect(malformed.hostMetrics()).rejects.toMatchObject({ code: "invalid_response" });
    const unavailable = createAcornFoxIntegrationClient(async () => json({ code: "not_ready", message: "功能未就绪" }, 503));
    await expect(unavailable.setupState()).rejects.toMatchObject({ status: 503, code: "not_ready" });

    const falseEvidence = createAcornFoxIntegrationClient(async () => json({ operation_id: "o", operation_type: "probe", status: "verified", accepted_at: "2030-01-01T00:00:00Z", updated_at: "2030-01-01T00:00:01Z", evidence: { kind: "runtime_observation", verdict: "unhealthy", observed_at: "2030-01-01T00:00:01Z" } }));
    await expect(falseEvidence.operationResult("a", "o")).rejects.toMatchObject({ code: "invalid_response" });
    await expect(unavailable.sourceUpdate("a", { baseSourceRevisionId: "s", ref: "main" }, "same-request")).rejects.toMatchObject({ status: 503 });
  });
});
