import { beforeEach, describe, expect, it } from "vitest";
import {
  createCoreAuthClient,
  AcornFoxRequestError,
  type CoreAuthClient,
  imageOperationDecoder,
  managedImageApplicationsDecoder,
  imageLifecycleOperationDecoder,
  type ImageLifecycleOperation,
  type ImageOperation,
  managedImageObservationDecoder,
  managedImageMetricsDecoder,
  managedImageMetricsRecentDecoder,
  imageDomainOperationDecoder,
  imageDomainCurrentDecoder,
  hostMetricsDecoder,
  hostMetricsRecentDecoder,
} from "../shared/auth-transport";
import { formatCoreCliHelp } from "./CoreHelp";
import { prepareImageLifecycleAttempt, bindImageLifecycleResponse, lifecycleLocked, availableImageLifecycleActions, visibleImageEndpoint, validateImageDeploymentReadback, readSavedImageApplication, savedImageSelectionLocked, bindManagedImageObservation, bindManagedImageMetrics, createManagedImageReadQueue, imageMemorySegments, currentManagedImageObservation, readCurrentImageDomain, imageDomainLocked, imageDomainSelectionLocked, bindImageDomainOperation } from "./ImageDeployView";
import { LOCAL_CSRF_COOKIE_NAME } from "../acornfox/csrf";

const sessionFixture = {
  authenticated: true,
  idle_expires_at: "2026-09-26T00:00:00Z",
  absolute_expires_at: "2026-09-27T00:00:00Z",
};

const validAvailableMetricsFixture = {
  schema_version: 1,
  availability: "available",
  observed_at: "2026-09-26T19:00:00Z",
  stale_after_seconds: 15,
  cpu: { logical_cores: 4, usage_percent: 15.5 },
  memory: { total_bytes: 16000000, available_bytes: 8000000, used_bytes: 8000000 },
  disk: { mountpoint: "/", total_bytes: 100000000, free_bytes: 50000000, used_bytes: 50000000 },
  network: { interface: "eth0", rx_bytes_per_second: 1000, tx_bytes_per_second: 500 },
};

describe("Core Auth Transport Contract Table", () => {
  type TableRow = [
    action: string,
    invoke: (c: CoreAuthClient) => Promise<unknown>,
    method: string,
    path: string,
    status: number,
    body: unknown,
    mockRes: unknown,
    requiresCsrf: boolean,
  ];

  const table: TableRow[] = [
    ["setupState", (c) => c.setupState(), "GET", "/api/v1/acornfox/setup", 200, undefined, { state: "initialized" }, false],
    ["setup", (c) => c.setup({ setupToken: "tok", password: "pwd" }), "POST", "/api/v1/acornfox/setup", 201, { setup_token: "tok", password: "pwd" }, { initialized: true }, false],
    ["login", (c) => c.login("secret"), "POST", "/api/v1/acornfox/auth/login", 200, { password: "secret" }, sessionFixture, false],
    ["session", (c) => c.session(), "GET", "/api/v1/acornfox/auth/session", 200, undefined, sessionFixture, false],
    ["changePassword", (c) => c.changePassword("old", "new"), "POST", "/api/v1/acornfox/auth/password", 204, { current_password: "old", new_password: "new" }, null, true],
    ["logout", (c) => c.logout(), "POST", "/api/v1/acornfox/auth/logout", 204, undefined, null, true],
    ["coreStatus", (c) => c.coreStatus(), "GET", "/api/v1/acornfox/core/status", 200, undefined, { storage: "sqlite", executor: { container: false, source_build: false, gateway: false } }, false],
    ["hostMetrics", (c) => c.hostMetrics(), "GET", "/api/v1/acornfox/host/metrics", 200, undefined, validAvailableMetricsFixture, false],
    ["hostMetricsRecent", (c) => c.hostMetricsRecent(60), "GET", "/api/v1/acornfox/host/metrics/recent", 200, undefined, { schema_version: 1, availability: "available", generated_at: "2026-09-26T19:00:00Z", capacity: 360, retention_seconds: 1800, points: [validAvailableMetricsFixture] }, false],
  ];

  it.each(table)("verifies %s transport contract", async (_, invoke, method, path, status, body, mockRes, requiresCsrf) => {
    let captured: { url: string; method?: string; headers: Headers; body?: string } | undefined;
    const fetcher = async (input: RequestInfo | URL, init?: RequestInit) => {
      captured = { url: String(input), method: init?.method ?? "GET", headers: new Headers(init?.headers), body: init?.body ? String(init.body) : undefined };
      return status === 204 ? new Response(null, { status: 204 }) : new Response(JSON.stringify(mockRes), { status, headers: { "Content-Type": "application/json" } });
    };

    Object.defineProperty(globalThis, "document", { configurable: true, value: { cookie: `${LOCAL_CSRF_COOKIE_NAME}=csrf_tok` } });
    Object.defineProperty(globalThis, "window", { configurable: true, value: { location: { origin: "http://127.0.0.1:4175" } } });

    const client = createCoreAuthClient(fetcher);
    await invoke(client);

    expect(captured?.url).toBe(path);
    expect(captured?.method).toBe(method);
    if (body) expect(JSON.parse(captured?.body ?? "{}")).toEqual(body);
    if (requiresCsrf) expect(captured?.headers.get("X-AcornFox-CSRF")).toBe("csrf_tok");
  });

  it.each([
    ["login with empty password", (c: CoreAuthClient) => c.login("")],
    ["setup with empty token", (c: CoreAuthClient) => c.setup({ setupToken: "", password: "pwd" })],
    ["setup with empty password", (c: CoreAuthClient) => c.setup({ setupToken: "tok", password: "" })],
    ["changePassword empty current", (c: CoreAuthClient) => c.changePassword("", "new")],
    ["changePassword empty new", (c: CoreAuthClient) => c.changePassword("old", "")],
  ])("synchronously throws on %s", (_, action) => {
    const client = createCoreAuthClient();
    expect(() => action(client)).toThrow(AcornFoxRequestError);
  });

  it("strictly validates ISO date session expiry and requires CSRF on mutation", async () => {
    const badDateFetcher = async () => new Response(JSON.stringify({ authenticated: true, idle_expires_at: "bad", absolute_expires_at: "bad" }), { status: 200, headers: { "Content-Type": "application/json" } });
    await expect(createCoreAuthClient(badDateFetcher).session()).rejects.toThrow(AcornFoxRequestError);

    Object.defineProperty(globalThis, "document", { configurable: true, value: { cookie: "" } });
    const noCookieClient = createCoreAuthClient(async () => new Response(null, { status: 204 }));
    await expect(noCookieClient.logout()).rejects.toThrow(AcornFoxRequestError);
  });

  it("transmits AbortSignal to fetcher for hostMetrics and hostMetricsRecent", async () => {
    let capturedSignal: AbortSignal | undefined;
    const fetcher = async (_: RequestInfo | URL, init?: RequestInit) => {
      capturedSignal = init?.signal as AbortSignal;
      return new Response(JSON.stringify(validAvailableMetricsFixture), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    };
    const client = createCoreAuthClient(fetcher);
    const controller = new AbortController();
    await client.hostMetrics(controller.signal);
    expect(capturedSignal).toBe(controller.signal);
  });

  it("does not trigger auth failure callback when a 401 returns after request was aborted", async () => {
    let authFailureCalled = false;
    const controller = new AbortController();
    const delayed401Fetcher = async () => {
      controller.abort();
      return new Response(
        JSON.stringify({ code: "unauthorized", message: "session expired" }),
        { status: 401, headers: { "Content-Type": "application/json" } },
      );
    };
    const client = createCoreAuthClient(delayed401Fetcher, () => {
      authFailureCalled = true;
    });
    await expect(client.hostMetrics(controller.signal)).rejects.toThrow("aborted");
    expect(authFailureCalled).toBe(false);
  });
});

describe("Core CLI Help Contract", () => {
  it("formats genuine core operations with loopback origin and rejects public HTTP", () => {
    const loopbackHelp = formatCoreCliHelp("http://127.0.0.1:4175");
    expect(loopbackHelp).toContain("acornfox login --local --server http://127.0.0.1:4175");
    expect(loopbackHelp).toContain("acornfox session");
    expect(loopbackHelp).toContain("acornfox password change");
    expect(loopbackHelp).toContain("acornfox logout");
    expect(loopbackHelp).toContain("acornfox host metrics");
    expect(loopbackHelp).toContain("acornfox host recent");
    expect(loopbackHelp).not.toContain("acornfox check");
    expect(loopbackHelp).not.toContain("acornfox plan");
    expect(loopbackHelp).not.toContain("acornfox-admin reset-password");
    expect(loopbackHelp).not.toContain("重新初始化");

    const publicHttpHelp = formatCoreCliHelp("http://public.example.com");
    expect(publicHttpHelp).not.toContain("acornfox login --server http://public.example.com");
    expect(publicHttpHelp).toContain("公网 HTTP 不支持明文凭据登录");

    const fallbackHelp = formatCoreCliHelp();
    expect(fallbackHelp).toContain("acornfox login --local --server http://127.0.0.1:PORT");
  });
});

describe("Host Metrics Decoder Strictness Contract", () => {
  it("decodes valid fully-populated available metrics and initial empty warming_up", () => {
    const available = hostMetricsDecoder(validAvailableMetricsFixture);
    expect(available.availability).toBe("available");
    expect(available.cpu?.usage_percent).toBe(15.5);

    const initialWarming = hostMetricsDecoder({
      schema_version: 1,
      availability: "warming_up",
      stale_after_seconds: 15,
    });
    expect(initialWarming.availability).toBe("warming_up");
    expect(initialWarming.cpu).toBeUndefined();
  });

  it("rejects available metrics missing core fields or with incomplete objects", () => {
    // Missing observed_at
    const noObserved = { ...validAvailableMetricsFixture, observed_at: undefined };
    expect(() => hostMetricsDecoder(noObserved)).toThrow(AcornFoxRequestError);

    // Missing cpu
    const noCpu = { ...validAvailableMetricsFixture, cpu: undefined };
    expect(() => hostMetricsDecoder(noCpu)).toThrow(AcornFoxRequestError);

    // Available cpu missing usage_percent
    const noUsage = {
      ...validAvailableMetricsFixture,
      cpu: { logical_cores: 4 },
    };
    expect(() => hostMetricsDecoder(noUsage)).toThrow(AcornFoxRequestError);

    // Empty memory object
    const emptyMem = { ...validAvailableMetricsFixture, memory: {} };
    expect(() => hostMetricsDecoder(emptyMem)).toThrow(AcornFoxRequestError);

    // Invalid calendar date
    const badDate = { ...validAvailableMetricsFixture, observed_at: "2026-02-30T10:00:00Z" };
    expect(() => hostMetricsDecoder(badDate)).toThrow(AcornFoxRequestError);

    // Invalid calendar date with timezone offset
    const badDateOffset = { ...validAvailableMetricsFixture, observed_at: "2026-02-30T12:00:00+08:00" };
    expect(() => hostMetricsDecoder(badDateOffset)).toThrow(AcornFoxRequestError);
  });

  it("rejects unavailable or unsupported carrying metric data", () => {
    const badUnavailable = {
      schema_version: 1,
      availability: "unavailable",
      stale_after_seconds: 15,
      cpu: { logical_cores: 4 },
    };
    expect(() => hostMetricsDecoder(badUnavailable)).toThrow(AcornFoxRequestError);
  });

  it("strictly enforces recent history constraints: points bound, ordering, and no empty points", () => {
    // Rejects points exceeding request limit
    const exceeded = {
      schema_version: 1,
      availability: "available",
      generated_at: "2026-09-26T19:00:00Z",
      capacity: 360,
      retention_seconds: 1800,
      points: [validAvailableMetricsFixture, validAvailableMetricsFixture],
    };
    expect(() => hostMetricsRecentDecoder(exceeded, 1)).toThrow(AcornFoxRequestError);

    // Rejects history point with no observed_at (empty warming_up in history)
    const emptyWarmingInHistory = {
      schema_version: 1,
      availability: "warming_up",
      generated_at: "2026-09-26T19:00:00Z",
      capacity: 360,
      retention_seconds: 1800,
      points: [{ schema_version: 1, availability: "warming_up", stale_after_seconds: 15 }],
    };
    expect(() => hostMetricsRecentDecoder(emptyWarmingInHistory, 60)).toThrow(AcornFoxRequestError);

    // Rejects non-monotonic history points
    const p1 = { ...validAvailableMetricsFixture, observed_at: "2026-09-26T18:55:00Z" };
    const p2 = { ...validAvailableMetricsFixture, observed_at: "2026-09-26T18:50:00Z" };
    const nonMonotonic = {
      schema_version: 1,
      availability: "available",
      generated_at: "2026-09-26T19:00:00Z",
      capacity: 360,
      retention_seconds: 1800,
      points: [p1, p2], // p1 > p2, reverse order!
    };
    expect(() => hostMetricsRecentDecoder(nonMonotonic, 60)).toThrow(AcornFoxRequestError);
  });
});


describe("Native image transport safety", () => {
  beforeEach(() => { Object.defineProperty(globalThis, "window", { configurable: true, value: { location: { origin: "http://127.0.0.1:4175" } } }); });
  it("requires CSRF for both image mutations and preserves confirmation identity", async () => {
    const calls: RequestInit[] = [];
    const body = { plan_id: "plan-1", plan_digest: `sha256:${"a".repeat(64)}`, idempotency_key: "same-intent-key" };
    const fetcher = async (_: RequestInfo | URL, init?: RequestInit) => {
      calls.push(init ?? {});
      return new Response(JSON.stringify({ code: "conflict", message: "already in progress" }), { status: 409 });
    };
    Object.defineProperty(globalThis, "document", { configurable: true, value: { cookie: "" } });
    const client = createCoreAuthClient(fetcher);
    await expect(client.createImagePlan({ app_name: "app", image: "nginx:alpine" })).rejects.toMatchObject({ code: "csrf_missing" });
    await expect(client.confirmImagePlan(body)).rejects.toMatchObject({ code: "csrf_missing" });
    expect(calls).toHaveLength(0);
    Object.defineProperty(globalThis, "document", { configurable: true, value: { cookie: `${LOCAL_CSRF_COOKIE_NAME}=csrf_tok` } });
    for (let i = 0; i < 2; i++) await expect(client.confirmImagePlan(body)).rejects.toMatchObject({ status: 409 });
    expect(calls.map((call) => JSON.parse(String(call.body)))).toEqual([body, body]);
    expect(calls.every((call) => new Headers(call.headers).get("X-AcornFox-CSRF") === "csrf_tok" && call.credentials === "include" && call.redirect === "error")).toBe(true);
  });

  it("rejects false operation success and endpoint scope while accepting absent optional diagnostics", () => {
    const fixture = { operation_id: "op-1", application_id: "app-1", environment_id: "env-1", operation_type: "deploy_image", state: "unknown", plan_id: "plan-1", plan_digest: `sha256:${"a".repeat(64)}`, task_id: "task-1", created_at: "2026-09-27T00:00:00Z", updated_at: "2026-09-27T00:00:00Z" };
    expect(imageOperationDecoder(fixture).state).toBe("unknown");
    expect(() => imageOperationDecoder({ ...fixture, state: "ready" })).toThrow(AcornFoxRequestError);
    const result = { deployment_id: "dep-1", release_id: "rel-1", status: "running", host_ip: "127.0.0.1", host_port: 32000, container_port: 80, endpoint: "http://127.0.0.1:32000" };
    expect(imageOperationDecoder({ ...fixture, state: "succeeded", result }).result?.endpoint).toBe(result.endpoint);
    expect(() => imageOperationDecoder({ ...fixture, result: { ...result, endpoint: "https://public.example" } })).toThrow(AcornFoxRequestError);
    expect(() => imageOperationDecoder({ ...fixture, action_required: "true" })).toThrow(AcornFoxRequestError);
    expect(imageOperationDecoder({ ...fixture, state: "failed", reason: "sanitized failure", action_required: true }).reason).toBe("sanitized failure");
  });
});


describe("Native image lifecycle retained intent", () => {
  beforeEach(() => { Object.defineProperty(globalThis, "window", { configurable: true, value: { location: { origin: "http://127.0.0.1:4175" } } }); });
  const hash = `sha256:${"a".repeat(64)}`;
  const deployment: ImageOperation = { operation_id: "op-deploy", application_id: "app-1", environment_id: "env-1", plan_id: "plan-1", plan_digest: hash, state: "succeeded", result: { deployment_id: "dep-1", release_id: "rel-1", status: "running", container_id: "same-cid", image_id: hash, host_ip: "127.0.0.1", host_port: 32000, container_port: 80, endpoint: "http://127.0.0.1:32000" } };
  const accepted: ImageLifecycleOperation = { operation_id: "op-stop", task_id: "task-stop", deployment_id: "dep-1", release_id: "rel-1", application_id: "app-1", environment_id: "env-1", deploy_operation_id: "op-deploy", plan_id: "plan-1", plan_digest: hash, manifest_digest: hash, container_id: "same-cid", image_id: hash, host_port: 32000, container_port: 80, action: "stop", state: "pending", created_at: "2026-09-28T00:00:00Z", recovery_required: false };

  it("retains the pending navigation intent, aborts a late response and retries the same key", async () => {
    Object.defineProperty(globalThis, "document", { configurable: true, value: { cookie: `${LOCAL_CSRF_COOKIE_NAME}=csrf_tok` } });
    let release: (response: Response) => void = (_response) => { throw new Error("fixture request was not sent"); };
    const bodies: unknown[] = [];
    const client = createCoreAuthClient(async (_path, init) => {
      bodies.push(JSON.parse(String(init?.body)));
      expect(new Headers(init?.headers).get("Idempotency-Key")).toBe("same-key");
      if (bodies.length === 1) return new Promise<Response>((resolve) => { release = resolve; });
      return new Response(JSON.stringify(accepted), { status: 200 });
    });
    const intent = prepareImageLifecycleAttempt(deployment, "stop", "same-key", null, hash);
    const navigation = new AbortController();
    const pending = client.createImageLifecycle(intent.deploymentId, { action: intent.action, idempotency_key: intent.key }, navigation.signal);
    navigation.abort();
    release(new Response(JSON.stringify(accepted), { status: 200 }));
    await expect(pending).rejects.toMatchObject({ name: "AbortError" });
    expect(intent.operationId).toBe("");
    expect(lifecycleLocked(intent)).toBe(true);
    expect(() => prepareImageLifecycleAttempt(deployment, "restart", "new-key", intent, hash)).toThrow();
    const response = await client.createImageLifecycle(intent.deploymentId, { action: intent.action, idempotency_key: intent.key });
    const retained = bindImageLifecycleResponse(intent, response);
    expect(retained.key).toBe(intent.key);
    expect(retained.operationId).toBe("op-stop");
    expect(bodies).toEqual([{ action: "stop", idempotency_key: "same-key" }, { action: "stop", idempotency_key: "same-key" }]);
    expect(visibleImageEndpoint(deployment, retained)).toBe("");
  });

  it("keeps unknown commands locked and hides stopped URLs until latest deployment readback", () => {
    const intent = prepareImageLifecycleAttempt(deployment, "stop", "same-key", null, hash);
    const unknown = bindImageLifecycleResponse(intent, imageLifecycleOperationDecoder({ ...accepted, state: "unknown", recovery_required: true }));
    expect(imageLifecycleOperationDecoder({ ...accepted, state: "unknown", recovery_required: true, reason: "连接中断，正在核对已有资源" }).reason).toBe("连接中断，正在核对已有资源");
    expect(() => imageLifecycleOperationDecoder({ ...accepted, reason: "过期失败信息" })).toThrow(AcornFoxRequestError);
    expect(lifecycleLocked(unknown)).toBe(true);
    expect(visibleImageEndpoint(deployment, unknown)).toBe("");
    expect(() => bindImageLifecycleResponse(unknown, { ...accepted, operation_id: "different-op" })).toThrow();
    const stopped = bindImageLifecycleResponse(unknown, imageLifecycleOperationDecoder({ ...accepted, state: "succeeded", result: { running: false, verified_identity: true, container_id: "same-cid", image_id: hash, manifest_digest: hash, host_port: 32000, container_port: 80, endpoint_ready: false, observed_at: "2026-09-28T00:00:01Z" } }));
    expect(lifecycleLocked(stopped)).toBe(false);
    expect(visibleImageEndpoint(deployment, null, false)).toBe("");
    expect(visibleImageEndpoint(deployment, stopped, false)).toBe("");
    expect(() => validateImageDeploymentReadback({ ...deployment, result: { ...deployment.result!, container_id: "wrong-cid" } }, stopped)).toThrow();
    expect(visibleImageEndpoint(deployment, stopped, true)).toBe("");
    const latest = { ...deployment, result: { ...deployment.result!, status: "stopped", endpoint: undefined } };
    expect(availableImageLifecycleActions(latest)).toEqual(["start"]);
    const next = prepareImageLifecycleAttempt(latest, "start", "next-key", stopped, hash);
    expect(next.containerId).toBe(intent.containerId);
    expect(next.deploymentId).toBe(intent.deploymentId);
  });

  it("requires lifecycle CSRF, actual HTTP 200 acceptance and exact command identity", async () => {
    const calls: RequestInit[] = [];
    let response = accepted;
    let status = 200;
    const client = createCoreAuthClient(async (_path, init) => { calls.push(init ?? {}); return new Response(JSON.stringify(response), { status }); });
    Object.defineProperty(globalThis, "document", { configurable: true, value: { cookie: "" } });
    await expect(client.createImageLifecycle("dep-1", { action: "stop", idempotency_key: "same-key" })).rejects.toMatchObject({ code: "csrf_missing" });
    expect(calls).toHaveLength(0);
    Object.defineProperty(globalThis, "document", { configurable: true, value: { cookie: `${LOCAL_CSRF_COOKIE_NAME}=csrf_tok` } });
    status = 201;
    await expect(client.createImageLifecycle("dep-1", { action: "stop", idempotency_key: "same-key" })).rejects.toMatchObject({ code: "invalid_response" });
    status = 200; response = { ...accepted, deployment_id: "other-deployment" };
    await expect(client.createImageLifecycle("dep-1", { action: "stop", idempotency_key: "same-key" })).rejects.toMatchObject({ code: "invalid_response" });
    response = { ...accepted, state: "unknown", recovery_required: true };
    await expect(client.createImageLifecycle("dep-1", { action: "stop", idempotency_key: "same-key" })).rejects.toMatchObject({ code: "invalid_response" });
    response = { ...accepted, operation_id: "wrong-op" };
    await expect(client.imageLifecycleOperation("op-stop")).rejects.toMatchObject({ code: "invalid_response" });
  });
});

describe("saved managed-image application selection", () => {
  it("uses only normal GETs to recover a failed application and rejects private summaries", async () => {
    const digest = `sha256:${"a".repeat(64)}`;
    const item = { application_id: "app-saved", name: "Original failed app", environment_id: "env-saved", plan_id: "plan-saved", plan_digest: digest, deploy_operation_id: "op-saved", deploy_state: "failed" as const, updated_at: "2026-09-28T00:00:00Z" };
    let list: { items: unknown[]; truncated: boolean } = { items: [item], truncated: false };
    expect(managedImageApplicationsDecoder(list).items[0]?.application_id).toBe("app-saved");
    expect(() => managedImageApplicationsDecoder({ ...list, items: [{ ...item, canonical_input: { environment: "private" } }] })).toThrow(AcornFoxRequestError);
    const calls: string[] = [];
    let operation: Record<string, unknown> = { operation_id: "op-saved", application_id: "app-saved", environment_id: "env-saved", operation_type: "deploy_image", state: "failed", plan_id: "plan-saved", plan_digest: digest, task_id: "task-saved", created_at: item.updated_at, updated_at: item.updated_at, reason: "retained real failure", action_required: true };
    const plan = { admin_id: "adm-saved", created_at: item.updated_at, updated_at: item.updated_at, resolver_provenance: { provider: "registryhttp", evidence_ref: "ev-saved", digest, resolved_at: item.updated_at }, id: "plan-saved", app_name: "Original failed app", status: "planned", plan_digest: digest, canonical_input: { app_name: "Original failed app", repository: "ghcr.io/acme/app", resolved_ref: "pinned", port: 80, resources: { cpu_millis: 100, memory_bytes: 1048576 } }, resolved_image: { repository: "ghcr.io/acme/app", digest, os: "linux", architecture: "amd64" }, missing_inputs: [] };
    let lifecycleResponse: Record<string, unknown> | null = null;
    const client = createCoreAuthClient(async (path, init) => {
      calls.push(`${init?.method ?? "GET"} ${String(path)}`);
      return new Response(JSON.stringify(String(path).includes("image-apps") ? list : String(path).includes("image-plans") ? plan : String(path).includes("image-lifecycle-operations") ? lifecycleResponse : operation), { status: 200 });
    });
    const discovered = await client.imageApps();
    const value = await readSavedImageApplication(client, discovered.items[0]!, new AbortController().signal);
    expect(value.operation.operation_id).toBe("op-saved"); expect(value.operation.state).toBe("failed"); expect(value.lifecycle).toBeNull();
    expect(calls).toHaveLength(4); expect(calls.every((value) => value.startsWith("GET "))).toBe(true);
    await expect(readSavedImageApplication(client, { ...item, application_id: "other-app" }, new AbortController().signal)).rejects.toThrow();
    await expect(client.imageApps(101)).rejects.toMatchObject({ code: "invalid_input" });
    operation = { ...operation, reason: undefined, action_required: undefined, state: "succeeded", result: { deployment_id: "dep-saved", release_id: "rel-saved", status: "running", container_id: "cid-saved", image_id: digest, host_ip: "127.0.0.1", host_port: 39081, container_port: 80, endpoint: "http://127.0.0.1:39081" } };
    lifecycleResponse = { operation_id: "cmd-saved", task_id: "task-command", deployment_id: "dep-saved", release_id: "rel-saved", application_id: "app-saved", environment_id: "env-saved", deploy_operation_id: "op-saved", plan_id: "plan-saved", plan_digest: digest, manifest_digest: digest, container_id: "cid-saved", image_id: digest, host_port: 39081, container_port: 80, action: "stop", state: "unknown", recovery_required: true, created_at: item.updated_at };
    const activeItem = { ...item, active_command: { operation_id: "cmd-saved", action: "stop" as const, state: "unknown" as const } };
    list = { items: [{ ...activeItem, deployment_id: "dep-saved", deployment_state: "running" }], truncated: false };
    const restored = await readSavedImageApplication(client, item, new AbortController().signal);
    expect(restored.lifecycle?.key).toBe(""); expect(restored.lifecycle?.operationId).toBe("cmd-saved");
    expect(lifecycleLocked(restored.lifecycle)).toBe(true); expect(visibleImageEndpoint(restored.operation, restored.lifecycle)).toBe("");
    lifecycleResponse = { ...lifecycleResponse, state: "failed", recovery_required: false, reason: "earlier command failed" };
    list = { items: [{ ...item, deployment_id: "dep-saved", deployment_state: "running", last_command: { operation_id: "cmd-saved", action: "stop", state: "failed" } }], truncated: false };
    const historical = await readSavedImageApplication(client, { ...item, last_command: { operation_id: "cmd-saved", action: "stop", state: "failed" } }, new AbortController().signal);
    expect(historical.lifecycle).toBeNull(); expect(historical.history?.state).toBe("failed");
    expect(savedImageSelectionLocked(true, "known-confirm-key", null, null)).toBe(true);
    expect(savedImageSelectionLocked(false, "", historical.operation, { ...restored.lifecycle!, key: "known-command-key" })).toBe(true);
    expect(savedImageSelectionLocked(true, "known-confirm-key", historical.operation, null)).toBe(false);

    expect(visibleImageEndpoint(historical.operation, historical.lifecycle)).toBe("http://127.0.0.1:39081");
    list = { items: [{ ...activeItem, deployment_id: "dep-saved", deployment_state: "running" }], truncated: false };
    lifecycleResponse = { ...lifecycleResponse, reason: undefined, state: "succeeded", recovery_required: false, result: { running: false, verified_identity: true, container_id: "cid-saved", image_id: digest, manifest_digest: digest, host_port: 0, container_port: 0, endpoint_ready: false, observed_at: item.updated_at } };
    const before = calls.length;
    // The transport responds with old running on the first deploy GET, then
    // the current stopped projection after the command's terminal observation.
    let deployReads = 0;
    const terminalClient = createCoreAuthClient(async (path, init) => {
      calls.push(`${init?.method ?? "GET"} ${String(path)}`);
      const route = String(path);
      if (route.includes("image-apps")) return new Response(JSON.stringify(list));
      if (route.includes("image-plans")) return new Response(JSON.stringify(plan));
      if (route.includes("image-lifecycle-operations")) return new Response(JSON.stringify(lifecycleResponse));
      deployReads += 1;
      const current = deployReads === 1 ? operation : { ...operation, result: { ...(operation.result as Record<string, unknown>), status: "stopped", endpoint: undefined } };
      return new Response(JSON.stringify(current));
    });
    const terminalRestore = await readSavedImageApplication(terminalClient, item, new AbortController().signal);
    expect(deployReads).toBe(2); expect(calls.length - before).toBe(5);
    expect(availableImageLifecycleActions(terminalRestore.operation)).toEqual(["start"]);
    expect(visibleImageEndpoint(terminalRestore.operation, terminalRestore.lifecycle)).toBe("");
    list = { items: [], truncated: true };
    await expect(readSavedImageApplication(client, item, new AbortController().signal)).rejects.toThrow();
    expect(calls.every((value) => value.startsWith("GET "))).toBe(true);
  });
});


describe("managed image observation transport", () => {
  const digest = `sha256:${"a".repeat(64)}`;
  const state = () => ({ running: true, verified_identity: true, container_id: "cid-A", image_id: digest, manifest_digest: digest, host_port: 39081, container_port: 80, endpoint_ready: false, observed_at: new Date().toISOString() });
  it("requires real bounded sample/log flags and permits slight browser clock skew", () => {
    const sample = { state: state(), source_limited: false, records: [{ stream: "stdout", data: "actual bounded line" }] };
    expect(managedImageObservationDecoder(sample).state.running).toBe(true);
    expect(managedImageObservationDecoder({ ...sample, state: { ...sample.state, observed_at: new Date(Date.now() + 200).toISOString() } }).state.endpoint_ready).toBe(false);
    const { source_limited: _omitted, ...missing } = sample;
    expect(() => managedImageObservationDecoder(missing)).toThrow(AcornFoxRequestError);
    expect(() => managedImageObservationDecoder({ ...sample, state: { ...sample.state, endpoint_ready: true } })).toThrow(AcornFoxRequestError);
    expect(() => managedImageObservationDecoder({ ...sample, records: [{ stream: "stdout", data: "界".repeat(2731) }] })).toThrow(AcornFoxRequestError);
    expect(() => managedImageObservationDecoder({ ...sample, state: { ...sample.state, observed_at: "1970-01-01T00:00:00Z" } })).toThrow(AcornFoxRequestError);
  });
  it("cancels old app reads and binds only the current CID/image/ports without mutation", async () => {
    let resolveOld: (response: Response) => void = () => { throw new Error("old request absent"); };
    const calls: { path: string; init?: RequestInit }[] = [];
    const client = createCoreAuthClient(async (path, init) => {
      calls.push({ path: String(path), init });
      if (String(path).endsWith("/dep-A/observation")) return new Promise<Response>((resolve) => { resolveOld = resolve; });
      return new Response(JSON.stringify({ state: { ...state(), container_id: "cid-B" }, records: [{ stream: "stderr", data: "[redacted]" }], source_limited: true }), { status: 200 });
    });
    const controller = new AbortController(); const oldRead = client.imageObservation("dep-A", controller.signal);
    controller.abort(); resolveOld(new Response(JSON.stringify({ state: state(), source_limited: false }), { status: 200 }));
    await expect(oldRead).rejects.toMatchObject({ name: "AbortError" });
    expect(currentManagedImageObservation("A", "B", 1, 2, controller.signal)).toBe(false);
    const latest = await client.imageLogs("dep-B", { tail: 64 });
    const target = { deploymentId: "dep-B", containerId: "cid-B", imageId: digest, manifestDigest: digest, hostPort: 39081, containerPort: 80 };
    expect(bindManagedImageObservation(latest, target).source_limited).toBe(true);
    expect(() => bindManagedImageObservation(latest, { ...target, containerId: "cid-A" })).toThrow();
    expect(calls.every((call) => (call.init?.method ?? "GET") === "GET" && call.init?.cache === "no-store")).toBe(true);
    expect(calls[0]?.init?.signal).toBe(controller.signal);
    expect(calls[1]?.path).toBe("/api/v1/acornfox/image-deployments/dep-B/logs?tail=64");
    const oversizedTail = createCoreAuthClient(async () => new Response(JSON.stringify({ state: state(), source_limited: true, records: [{ stream: "stdout", data: "one" }, { stream: "stderr", data: "two" }] }), { status: 200 }));
    await expect(oversizedTail.imageLogs("dep-B", { tail: 1 })).rejects.toMatchObject({ code: "invalid_response" });
    const count = calls.length;
    await expect(client.imageLogs("dep-B", { tail: 65 })).rejects.toMatchObject({ code: "invalid_input" });
    expect(calls).toHaveLength(count);
  });
});

describe("managed image metrics transport and trend", () => {
  const digest = `sha256:${"a".repeat(64)}`;
  const processStartedAt = new Date(Date.now() - 120000).toISOString();
  const state = () => ({ running: true, verified_identity: true, container_id: "cid-A", image_id: digest, manifest_digest: digest, host_port: 39081, container_port: 80, endpoint_ready: false, observed_at: new Date().toISOString() });
  const point = (offsetSeconds: number, segment_id: number, memory_usage_bytes?: number) => ({ segment_id, container_id: "cid-A", process_started_at: processStartedAt, observed_at: new Date(Date.now() + offsetSeconds * 1000).toISOString(), available: true, cpu_usage_millis: 2, ...(memory_usage_bytes === undefined ? {} : { memory_usage_bytes }) });
  const recent = () => {
    const samples = [point(-90, 1, 0), point(-60, 1), point(-30, 2, 1024), point(-10, 2, 2048)];
    return { deployment_id: "dep-A", container_id: "cid-A", history_epoch: new Date(Date.now() - 180000).toISOString(), history_start: samples[0].observed_at, current_segment_id: 2, scheduled: true, selection_limited: true, stale_after_seconds: 250, stale: false, recording_status: "recording", samples };
  };
  it("keeps absent metrics unavailable and splits memory at missing values or process segments", () => {
    const current = managedImageMetricsDecoder({ state: state(), available: true, sampled_at: new Date().toISOString(), process_started_at: new Date(Date.now() - 120000).toISOString(), memory_usage_bytes: 0 });
    expect(current.memory_usage_bytes).toBe(0);
    expect(current.cpu_percent).toBeUndefined();
    const history = managedImageMetricsRecentDecoder(recent(), 60);
    expect(imageMemorySegments(history).map((segment) => segment.map((sample) => sample.memory_usage_bytes))).toEqual([[0], [1024, 2048]]);
    const target = { deploymentId: "dep-A", containerId: "cid-A", imageId: digest, manifestDigest: digest, hostPort: 39081, containerPort: 80 };
    expect(bindManagedImageMetrics(current, history, target).recent.history_epoch).toBe(history.history_epoch);
    expect(() => bindManagedImageMetrics(current, history, { ...target, containerId: "other" })).toThrow();
    expect(() => managedImageMetricsRecentDecoder({ ...recent(), deployment_id: "dep-B" }, 60)).not.toThrow();
    expect(() => managedImageMetricsRecentDecoder({ ...recent(), samples: [...recent().samples, point(-5, 2, 0)] }, 4)).toThrow();
  });
  it("rejects contradictory recording states, invalid epochs, and changed identity inside one segment", () => {
    const value = recent();
    expect(() => managedImageMetricsRecentDecoder({ ...value, recording_status: "not_selected" }, 60)).toThrow();
    expect(() => managedImageMetricsRecentDecoder({ ...value, stale: true }, 60)).toThrow();
    expect(() => managedImageMetricsRecentDecoder({ ...value, stale_after_seconds: 35 }, 60)).toThrow();
    expect(() => managedImageMetricsRecentDecoder({ ...value, history_epoch: new Date().toISOString() }, 60)).toThrow();
    expect(() => managedImageMetricsRecentDecoder({ ...value, history_start: new Date().toISOString() }, 60)).toThrow();
    expect(() => managedImageMetricsRecentDecoder({ ...value, segment_start: new Date(Date.parse(value.history_epoch) - 1000).toISOString() }, 60)).toThrow();
    expect(() => managedImageMetricsRecentDecoder({ ...value, samples: [value.samples[0], { ...value.samples[1], container_id: "other" }, ...value.samples.slice(2)] }, 60)).toThrow();
    expect(() => managedImageMetricsRecentDecoder({ ...value, samples: [value.samples[0], { ...value.samples[1], process_started_at: new Date(Date.parse(processStartedAt) + 1000).toISOString() }, ...value.samples.slice(2)] }, 60)).toThrow();
    expect(() => managedImageMetricsRecentDecoder({ ...value, samples: [...value.samples.slice(0, 3), { segment_id: 2, container_id: "cid-A", observed_at: value.samples[3].observed_at, available: false, unavailable_reason: "read_unavailable", process_started_at: processStartedAt }] }, 60)).toThrow();
    expect(() => managedImageMetricsDecoder({ state: state(), available: true, sampled_at: new Date(Date.now() + 60000).toISOString(), process_started_at: processStartedAt, memory_usage_bytes: 1 })).toThrow();
    expect(() => managedImageMetricsRecentDecoder({ ...value, samples: [], history_start: undefined, current_segment_id: 0, stale: true, recording_status: "stale", reason: "sample_expired" }, 60)).not.toThrow();
  });
  it("serializes same-deployment reads and skips a cancelled queued read", async () => {
    const queue = createManagedImageReadQueue();
    const controller = new AbortController();
    let finishFirst: () => void = () => { throw new Error("missing first read"); };
    let running = 0, peak = 0, secondCalled = false;
    const first = queue(controller.signal, async () => {
      running++; peak = Math.max(peak, running);
      await new Promise<void>((resolve) => { finishFirst = resolve; });
      running--; return "current";
    });
    const second = queue(controller.signal, async () => { secondCalled = true; running++; peak = Math.max(peak, running); running--; return "recent"; });
    await Promise.resolve();
    expect(running).toBe(1);
    finishFirst();
    expect(await Promise.all([first, second])).toEqual(["current", "recent"]);
    expect(peak).toBe(1);
    expect(secondCalled).toBe(true);

    let release: () => void = () => { throw new Error("missing blocked read"); };
    const blocked = queue(controller.signal, async () => new Promise<void>((resolve) => { release = resolve; }));
    const stale = new AbortController(); let staleCalled = false;
    const queued = queue(stale.signal, async () => { staleCalled = true; return "old target"; });
    await Promise.resolve(); stale.abort(); release(); await blocked;
    await expect(queued).rejects.toMatchObject({ name: "AbortError" });
    expect(staleCalled).toBe(false);
  });
  it("binds GET paths and enforces byte and input bounds without sending an unsafe request", async () => {
    const calls: string[] = [];
    const client = createCoreAuthClient(async (path) => {
      calls.push(String(path));
      if (String(path).endsWith("/metrics")) return new Response(JSON.stringify({ state: state(), available: false, unavailable_reason: "read_unavailable", sampled_at: "0001-01-01T00:00:00Z", process_started_at: "0001-01-01T00:00:00Z" }), { status: 200 });
      return new Response(JSON.stringify(recent()), { status: 200 });
    });
    expect((await client.imageMetrics("dep-A")).available).toBe(false);
    expect((await client.imageMetricsRecent("dep-A", 4)).samples).toHaveLength(4);
    expect(calls).toEqual(["/api/v1/acornfox/image-deployments/dep-A/metrics", "/api/v1/acornfox/image-deployments/dep-A/metrics/recent?limit=4"]);
    await expect(client.imageMetricsRecent("dep-A", 361)).rejects.toMatchObject({ code: "invalid_input" });
    expect(calls).toHaveLength(2);
    const tooLarge = createCoreAuthClient(async () => new Response(JSON.stringify({ ...recent(), extra: "x".repeat(262144) }), { status: 200 }));
    await expect(tooLarge.imageMetricsRecent("dep-A", 60)).rejects.toMatchObject({ code: "invalid_response" });
  });
});

describe("saved-image custom-domain read and intent", () => {
  beforeEach(() => { Object.defineProperty(globalThis, "window", { configurable: true, value: { location: { origin: "http://127.0.0.1:4175" } } }); });
  const created = "2026-09-28T01:00:00Z";
  const operation = { operation_id: "op-domain", task_id: "task-domain", approval_id: "approval-domain", deployment_id: "dep-domain", hostname: "app.customer.example", action: "ensure", state: "succeeded", created_at: created, result: { observed_at: "2026-09-28T01:00:01Z", certificate_fingerprint: `sha256:${"a".repeat(64)}`, certificate_expires_at: "2026-10-28T01:00:01Z" } };
  const current = { operation, desired_public: true, local_route_state: "configured", deployment_status: "stopped", availability: "degraded" };
  it("restores stopped configuration with GET only and rejects a foreign operation or private field", async () => {
    const calls: string[] = [];
    let observed: Record<string, unknown> = operation;
    const client = createCoreAuthClient(async (path, init) => {
      calls.push(`${init?.method ?? "GET"} ${String(path)}`);
      return new Response(JSON.stringify(String(path).includes("image-domain-operations") ? observed : current), { status: 200 });
    });
    const value = await readCurrentImageDomain(client, "dep-domain", "stopped", new AbortController().signal);
    expect(value?.availability).toBe("degraded"); expect(value?.desired_public).toBe(true);
    expect(calls).toEqual(["GET /api/v1/acornfox/image-deployments/dep-domain/domain", "GET /api/v1/acornfox/image-domain-operations/op-domain"]);
    expect(() => imageDomainCurrentDecoder({ ...current, availability: "unverified" })).toThrow(AcornFoxRequestError);
    expect(() => imageDomainOperationDecoder({ ...operation, plan: { environment: "private" } })).toThrow(AcornFoxRequestError);
    observed = { ...operation, deployment_id: "dep-other" };
    await expect(readCurrentImageDomain(client, "dep-domain", "stopped", new AbortController().signal)).rejects.toThrow();
    const noDomain = createCoreAuthClient(async () => new Response(JSON.stringify({ code: "not_found", message: "not found" }), { status: 404 }));
    expect(await readCurrentImageDomain(noDomain, "dep-domain", "running", new AbortController().signal)).toBeNull();
  });
  it("keeps a known unknown key and sends one exact CSRF-bound POST only on user invocation", async () => {
    Object.defineProperty(globalThis, "document", { configurable: true, value: { cookie: `${LOCAL_CSRF_COOKIE_NAME}=csrf_tok` } });
    const calls: { path: string; init?: RequestInit }[] = [];
    const client = createCoreAuthClient(async (path, init) => {
      calls.push({ path: String(path), init });
      return new Response(JSON.stringify({ code: "conflict", message: "original in progress" }), { status: 409 });
    });
    const input = { hostname: "app.customer.example", action: "ensure" as const, idempotency_key: "known-domain-key" };
    const pending = { key: input.idempotency_key, deploymentId: "dep-domain", hostname: input.hostname, action: input.action, operationId: "", operation: null };
    expect(imageDomainLocked(pending)).toBe(true);
    await expect(client.createImageDomainCommand("dep-domain", input)).rejects.toMatchObject({ status: 409 });
    expect(calls).toHaveLength(1);
    expect(calls[0]?.path).toBe("/api/v1/acornfox/image-deployments/dep-domain/domain-commands");
    expect(calls[0]?.init?.method).toBe("POST");
    expect(JSON.parse(String(calls[0]?.init?.body))).toEqual(input);
    expect(new Headers(calls[0]?.init?.headers).get("Idempotency-Key")).toBe(input.idempotency_key);
    expect(new Headers(calls[0]?.init?.headers).get("X-AcornFox-CSRF")).toBe("csrf_tok");
    await expect(client.createImageDomainCommand("dep-domain", { ...input, hostname: "APP.customer.example" })).rejects.toThrow(AcornFoxRequestError);
    expect(calls).toHaveLength(1);
    const unknown = { ...operation, state: "unknown", reason: "local route outcome requires reconciliation", result: undefined };
    expect(bindImageDomainOperation(imageDomainOperationDecoder(unknown), "dep-domain", pending).state).toBe("unknown");
    expect(imageDomainSelectionLocked({ ...pending, key: "", operationId: "op-domain", operation: imageDomainOperationDecoder(unknown) }, null)).toBe(true);
    expect(imageDomainSelectionLocked(null, { ...imageDomainCurrentDecoder(current), operation: imageDomainOperationDecoder(unknown), availability: "degraded" })).toBe(true);
    expect(imageDomainSelectionLocked({ ...pending, operation: imageDomainOperationDecoder(operation) }, null)).toBe(false);
    expect(() => bindImageDomainOperation(imageDomainOperationDecoder(unknown), "dep-other", pending)).toThrow();
    const accepted = createCoreAuthClient(async () => new Response(JSON.stringify({ ...operation, state: "pending", result: undefined }), { status: 202 }));
    expect((await accepted.createImageDomainCommand("dep-domain", input)).state).toBe("pending");
  });
});
