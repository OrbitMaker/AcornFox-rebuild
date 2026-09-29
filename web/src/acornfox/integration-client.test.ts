import { createAcornFoxIntegrationClient } from "./integration-client";

type Seen = { url: string; init?: RequestInit };
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
const sha = (value: string) => `sha256:${value.repeat(64)}`;
const observationFixture = {
  availability: "available",
  observation: {
    observer: "administrator_client",
    application_id: "app_1",
    deployment_id: "dep_1",
    hostname: "delivery-x.apps.example.test",
    report_id: "access_report_0123456789abcdef0123456789abcdef",
    observed_at: "2026-09-07T12:00:00Z",
    dns: { state: "observed", addresses: ["1.1.1.1"] },
    tls: { state: "observed", certificate_sha256: sha("a") },
    https: {
      state: "observed",
      http_status: 200,
      response_sample_sha256: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      response_sample_bytes: 0,
      response_truncated: false,
    },
    received_at: "2030-01-01T00:00:00Z",
    expires_at: "2030-01-01T00:05:00Z",
  },
} as const;
const deploymentPlanFixture = {
  application_id: "app_1",
  source_revision_id: "s",
  repository_url: "https://github.com/example/app.git",
  ref: "main",
  commit: "a".repeat(40),
  dockerfile: {
    status: "ready",
    path: "Dockerfile",
    digest: sha("d"),
    stage_count: 1,
    final_stage: { name: "final", index: 0, from: "scratch" },
  },
  ports: [{ port: 3000, protocol: "tcp", source: "dockerfile_expose" }],
  port_selection: { status: "selected", reason: "dockerfile_expose", selected_port: 3000, candidates: [3000] },
  healthcheck: { present: false },
  environment: [{ name: "PORT", value: "3000" }, { name: "API_TOKEN", redacted: true }],
  gaps: ["healthcheck_missing"],
  warnings: [],
  required_actions: [],
  ready_to_deploy: true,
} as const;

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
      if (url.endsWith("/deployment-plan")) return json(deploymentPlanFixture);
      if (url.endsWith("/metadata")) return json({ source_revision_id: "s", availability: "unavailable" });
      if (url.includes("/operations/")) return json({ operation_id: "o", operation_type: "probe", status: "verified", task_id: "t", deployment_id: "d", accepted_at: "2030-01-01T00:00:00Z", updated_at: "2030-01-01T00:00:01Z", evidence: { kind: "response_observation", verdict: "unhealthy", observed_at: "2030-01-01T00:00:01Z", http_status: 500 } });
      if (url.endsWith("/access-observation")) return json(observationFixture);
      return json({ deployment_id: "d", availability: "available", source_revision_id: "s", commit: "abc", ref: "main" });
    });
    await expect(api.setupState()).resolves.toBe("uninitialized");
    await expect(api.setup({ setupToken: "single-use", password: "not-a-real-password" })).resolves.toBeUndefined();
    await expect(api.hostMetrics()).resolves.toMatchObject({ availability: "warming_up", cpu: { logicalCores: 4 } });
    await expect(api.sourceMetadata("app id", "s id")).resolves.toEqual({ sourceRevisionId: "s", availability: "unavailable" });
    await expect(api.deploymentPlan("app id", "s id")).resolves.toMatchObject({ sourceRevisionId: "s", portSelection: { selectedPort: 3000 }, environment: [{ name: "PORT", value: "3000", redacted: false }, { name: "API_TOKEN", redacted: true }] });
    await expect(api.sourceUpdate("app id", { baseSourceRevisionId: "s id", ref: "main" }, "same-request")).resolves.toEqual({ sourceRevisionId: "s-next", status: "imported" });
    await expect(api.deploymentSource("app id", "d id")).resolves.toMatchObject({ deploymentId: "d", commit: "abc" });
    await expect(api.operationResult("app id", "o id")).resolves.toMatchObject({ operationId: "o", status: "verified", evidence: { verdict: "unhealthy", httpStatus: 500 } });
    await expect(api.accessObservation("app_1", "dep_1")).resolves.toEqual({
      availability: "available",
      observation: {
        observer: "administrator_client",
        applicationId: "app_1",
        deploymentId: "dep_1",
        hostname: "delivery-x.apps.example.test",
        reportId: "access_report_0123456789abcdef0123456789abcdef",
        observedAt: "2026-09-07T12:00:00Z",
        dns: { state: "observed", addresses: ["1.1.1.1"] },
        tls: { state: "observed", certificateSha256: sha("a") },
        https: {
          state: "observed",
          httpStatus: 200,
          responseSampleSha256: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          responseSampleBytes: 0,
          responseTruncated: false,
        },
        receivedAt: "2030-01-01T00:00:00Z",
        expiresAt: "2030-01-01T00:05:00Z",
      },
    });
    expect(seen.map((item) => item.url)).toEqual([
      "/api/v1/acornfox/setup",
      "/api/v1/acornfox/setup",
      "/api/v1/acornfox/host/metrics",
      "/api/v1/acornfox/apps/app%20id/sources/s%20id/metadata",
      "/api/v1/acornfox/apps/app%20id/sources/s%20id/deployment-plan",
      "/api/v1/acornfox/apps/app%20id/sources",
      "/api/v1/acornfox/apps/app%20id/deliveries/d%20id/source",
      "/api/v1/acornfox/apps/app%20id/operations/o%20id",
      "/api/v1/acornfox/apps/app_1/deliveries/dep_1/access-observation",
    ]);
    expect(new Headers(seen[1]?.init?.headers).get("X-AcornFox-CSRF")).toBe("csrf value");
    expect(new Headers(seen[1]?.init?.headers).get("Idempotency-Key")).toBeNull();
    expect(new Headers(seen[5]?.init?.headers).get("Idempotency-Key")).toBe("same-request");
    expect(JSON.parse(String(seen[5]?.init?.body))).toEqual({ base_source_revision_id: "s id", ref: "main" });
    expect(seen[6]?.init?.method).toBeUndefined();
    expect(new Headers(seen[6]?.init?.headers).get("X-AcornFox-CSRF")).toBeNull();
    expect(seen[8]?.init?.method).toBeUndefined();
    expect(new Headers(seen[8]?.init?.headers).get("X-AcornFox-CSRF")).toBeNull();
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

  it("rejects an access observation bound to another scope", async () => {
    const wrongScope = createAcornFoxIntegrationClient(async () => json({
      ...observationFixture,
      observation: { ...observationFixture.observation, deployment_id: "dep_other" },
    }));
    await expect(wrongScope.accessObservation("app_1", "dep_1")).rejects.toMatchObject({ code: "invalid_response" });
  });

  it("rejects unknown fields and state-dependent field leakage", async () => {
    const unknownField = createAcornFoxIntegrationClient(async () => json({
      ...observationFixture,
      observation: {
        ...observationFixture.observation,
        https: { ...observationFixture.observation.https, leaked: true },
      },
    }));
    await expect(unknownField.accessObservation("app_1", "dep_1")).rejects.toMatchObject({ code: "invalid_response" });

    const failedWithObservedFields = createAcornFoxIntegrationClient(async () => json({
      ...observationFixture,
      observation: {
        ...observationFixture.observation,
        https: {
          state: "failed",
          failure_code: "https_timeout",
          response_sample_bytes: 0,
          response_truncated: false,
        },
      },
    }));
    await expect(failedWithObservedFields.accessObservation("app_1", "dep_1")).rejects.toMatchObject({ code: "invalid_response" });

    const skippedWithObservedFields = createAcornFoxIntegrationClient(async () => json({
      ...observationFixture,
      observation: {
        ...observationFixture.observation,
        https: { state: "not_attempted", response_sample_bytes: 0, response_truncated: false },
      },
    }));
    await expect(skippedWithObservedFields.accessObservation("app_1", "dep_1")).rejects.toMatchObject({ code: "invalid_response" });

    for (const missing of ["response_sample_bytes", "response_truncated"] as const) {
      const https = { ...observationFixture.observation.https } as Record<string, unknown>;
      delete https[missing];
      const missingObservedField = createAcornFoxIntegrationClient(async () => json({
        ...observationFixture,
        observation: { ...observationFixture.observation, https },
      }));
      await expect(missingObservedField.accessObservation("app_1", "dep_1")).rejects.toMatchObject({ code: "invalid_response" });
    }

    const invalidAddress = createAcornFoxIntegrationClient(async () => json({
      ...observationFixture,
      observation: {
        ...observationFixture.observation,
        dns: { state: "observed", addresses: ["not-an-address"] },
      },
    }));
    await expect(invalidAddress.accessObservation("app_1", "dep_1")).rejects.toMatchObject({ code: "invalid_response" });
  });

  it("rejects inconsistent availability and layer states", async () => {
    const missingAvailableObservation = createAcornFoxIntegrationClient(async () => json({ availability: "available" }));
    await expect(missingAvailableObservation.accessObservation("app_1", "dep_1")).rejects.toMatchObject({ code: "invalid_response" });

    const notObservedWithObservation = createAcornFoxIntegrationClient(async () => json({
      availability: "not_observed",
      observation: observationFixture.observation,
    }));
    await expect(notObservedWithObservation.accessObservation("app_1", "dep_1")).rejects.toMatchObject({ code: "invalid_response" });

    const failedDNSStillAttemptsTLS = createAcornFoxIntegrationClient(async () => json({
      ...observationFixture,
      observation: {
        ...observationFixture.observation,
        dns: { state: "failed", failure_code: "dns_timeout" },
      },
    }));
    await expect(failedDNSStillAttemptsTLS.accessObservation("app_1", "dep_1")).rejects.toMatchObject({ code: "invalid_response" });
  });

  it("accepts an expired observation and a clean not-observed response", async () => {
    const expired = createAcornFoxIntegrationClient(async () => json({ ...observationFixture, availability: "expired" }));
    await expect(expired.accessObservation("app_1", "dep_1")).resolves.toMatchObject({
      availability: "expired",
      observation: { reportId: "access_report_0123456789abcdef0123456789abcdef" },
    });
    const empty = createAcornFoxIntegrationClient(async () => json({ availability: "not_observed" }));
    await expect(empty.accessObservation("app_1", "dep_1")).resolves.toEqual({ availability: "not_observed" });
  });
});

it("accepts local upload plans without inventing a repository URL", async () => {
  const local = { ...deploymentPlanFixture, source_type: "upload", repository_url: "", commit: "", ref: "upload_1" };
  const api = createAcornFoxIntegrationClient(async () => json(local));
  await expect(api.deploymentPlan("app", "source")).resolves.toMatchObject({ sourceType: "upload", repositoryUrl: "", commit: "" });
  const bad = createAcornFoxIntegrationClient(async () => json({ ...local, repository_url: "upload://private" }));
  await expect(bad.deploymentPlan("app", "source")).rejects.toMatchObject({ code: "invalid_response" });
});
