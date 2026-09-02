import {
  createAcornFoxClient,
  AcornFoxRequestError,
  expectedSuccessStatus,
} from "./client";

type Seen = { url: string; init: RequestInit };
const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });

describe("AcornFox API client", () => {
  const seen: Seen[] = [];
  const fetcher = async (
    input: RequestInfo | URL,
    init?: RequestInit,
  ): Promise<Response> => {
    seen.push({ url: String(input), init: init ?? {} });
    const url = String(input);
    if (url.endsWith("/auth/logout") || url.endsWith("/auth/password"))
      return new Response(null, { status: 204 });
    if (url.endsWith("/auth/session") || url.endsWith("/auth/login"))
      return json({
        authenticated: true,
        idle_expires_at: "2026-01-01T00:00:00Z",
        absolute_expires_at: "2026-01-02T00:00:00Z",
      });
    if (url.endsWith("/apps")) {
      return init?.method === "POST"
        ? json(
            {
              application: {
                id: "a",
                name: "A",
                created_at: "2026-01-01T00:00:00Z",
                updated_at: "2026-01-01T00:00:00Z",
              },
              source_revision_id: "s",
              operation_id: "o",
            },
            201,
          )
        : json({ items: [] });
    }
    if (url.includes("/sources?"))
      return json({ items: [], next_cursor: null });
    if (url.includes("/sources/"))
      return json({
        id: "s",
        application_id: "a",
        kind: "git_https",
        locator_sha256: "x",
        content_digest: "y",
        created_at: "2026-01-01T00:00:00Z",
        immutable: true,
      });
    if (url.includes("/deliveries?"))
      return json({ items: [], next_cursor: null });
    if (url.endsWith("/deliveries"))
      return json(
        {
          deployment_id: "d",
          operation_id: "o",
          task_id: "t",
          status: "accepted",
        },
        202,
      );
    if (url.endsWith("/restart") || url.endsWith("/redeploy"))
      return json(
        {
          deployment_id: "d",
          operation_id: "o",
          task_id: "t",
          status: "accepted",
        },
        202,
      );
    if (url.includes("/logs?"))
      return json({
        source: "build",
        availability: "available",
        items: [],
        next_cursor: null,
        retention_limited: false,
      });
    if (url.endsWith("/public-access") && init?.method === "PUT")
      return json({
        desired_public: true,
        url: "https://a.example.test",
        endpoint: { deployment_id: "d" },
        components: {
          internal_endpoint: "accepted",
          local_route: "desired",
          dns: "not_validated",
          tls: "not_validated",
          external: "not_validated",
        },
        status: "PENDING_EXTERNAL_VALIDATION",
      });
    if (url.endsWith("/public-access"))
      return json({
        desired_public: false,
        url: "https://a.example.test",
        endpoint: { deployment_id: "d" },
        components: {
          internal_endpoint: "accepted",
          local_route: "disabled",
          dns: "not_validated",
          tls: "not_validated",
          external: "not_validated",
        },
        status: "PUBLIC_DISABLED",
      });
    if (url.includes("/deliveries/"))
      return json({
        deployment: {
          id: "d",
          application_id: "a",
          environment_id: "e",
          release_id: "r",
          stage: "starting",
          created_at: "2026-01-01T00:00:00Z",
          updated_at: "2026-01-01T00:00:00Z",
        },
        desired: null,
        runtime: null,
        response: null,
      });
    return json({
      id: "a",
      name: "A",
      created_at: "2026-01-01T00:00:00Z",
      updated_at: "2026-01-01T00:00:00Z",
    });
  };
  beforeEach(() => {
    seen.length = 0;
    Object.defineProperty(globalThis, "document", {
      configurable: true,
      value: { cookie: "__Host-acornfox_csrf=token%201" },
    });
  });

  it("uses only the clean routes with exact mutation proof headers", async () => {
    const api = createAcornFoxClient(fetcher);
    await api.login("secret");
    await api.session();
    await api.logout();
    await api.changePassword("old", "new");
    await api.apps();
    await api.app("a b");
    await api.createApp({
      name: "A",
      repositoryUrl: "https://github.com/acme/a.git",
      ref: "main",
    });
    await api.sources("a b");
    await api.source("a b", "s c");
    await api.deployments("a b");
    await api.deploy("a b", "s c", 8080);
    await api.status("a b", "d c");
    await api.logs("a b", "d c", "runtime");
    await api.restart("a b", "d c");
    await api.redeploy("a b", "d c");
    await api.publicAccess("a b", "d c");
    await api.setPublicAccess("a b", "d c", true);
    expect(seen).toHaveLength(17);
    expect(seen.every((item) => item.url.startsWith("/api/v1/acornfox/"))).toBe(
      true,
    );
    expect(seen.map((item) => item.url)).toContain(
      "/api/v1/acornfox/apps/a%20b/deliveries/d%20c/logs?source=runtime&limit=50",
    );
    expect(seen.map((item) => item.url)).toContain(
      "/api/v1/acornfox/apps/a%20b/sources?limit=50",
    );
    const login = seen[0]!;
    const get = seen[1]!;
    const logout = seen[2]!;
    const create = seen[6]!;
    const deploy = seen[10]!;
    const access = seen[16]!;
    expect(login.init.method).toBe("POST");
    expect(login.init.redirect).toBe("error");
    expect(new Headers(login.init.headers).get("X-AcornFox-CSRF")).toBeNull();
    expect(new Headers(login.init.headers).get("Idempotency-Key")).toBeNull();
    expect(login.init.credentials).toBe("include");
    expect(get.init.method).toBeUndefined();
    expect(new Headers(get.init.headers).get("X-AcornFox-CSRF")).toBeNull();
    expect(new Headers(logout.init.headers).get("X-AcornFox-CSRF")).toBe(
      "token 1",
    );
    expect(new Headers(logout.init.headers).get("Idempotency-Key")).toBeNull();
    for (const item of [create, deploy, access]) {
      expect(new Headers(item.init.headers).get("X-AcornFox-CSRF")).toBe(
        "token 1",
      );
      expect(
        new Headers(item.init.headers).get("Idempotency-Key"),
      ).toBeTruthy();
    }
    expect(JSON.parse(String(create.init.body))).toEqual({
      name: "A",
      source: {
        type: "public_git",
        repository_url: "https://github.com/acme/a.git",
        ref: "main",
      },
    });
    expect(JSON.parse(String(deploy.init.body))).toEqual({
      source_revision_id: "s c",
      container_port: 8080,
    });
    expect(JSON.parse(String(access.init.body))).toEqual({ enabled: true });
  });

  it("maps server and transport failures without accepting malformed data", async () => {
    const forbidden = createAcornFoxClient(async () =>
      json({ code: "bad_input", message: "输入不正确" }, 422),
    );
    await expect(forbidden.apps()).rejects.toMatchObject({
      status: 422,
      code: "bad_input",
      kind: "failed",
    });
    const unavailable = createAcornFoxClient(async () => {
      throw new Error("network");
    });
    await expect(unavailable.apps()).rejects.toEqual(
      expect.objectContaining({
        status: undefined,
        code: "network_error",
        kind: "unavailable",
      }),
    );
    expect(new AcornFoxRequestError(401, "x", "x").kind).toBe("authentication");
  });

  it("fails closed on malformed records, invalid input, and authentication loss", async () => {
    const malformed = createAcornFoxClient(async () =>
      json({ authenticated: true }),
    );
    await expect(malformed.session()).rejects.toMatchObject({
      code: "invalid_response",
    });

    const called = vi.fn();
    const protectedClient = createAcornFoxClient(
      async () => json({ code: "session_expired", message: "请重新登录" }, 401),
      called,
    );
    await expect(protectedClient.apps()).rejects.toMatchObject({ status: 401 });
    expect(called).toHaveBeenCalledTimes(1);

    const noRequest = vi.fn(fetcher);
    const validating = createAcornFoxClient(noRequest);
    await expect(
      validating.createApp({
        name: " ",
        repositoryUrl: "http://example.test/app.git",
        ref: " ",
      }),
    ).rejects.toMatchObject({ status: 422 });
    expect(() => validating.deploy("a", "s", 65536)).toThrow(
      expect.objectContaining({ status: 422 }),
    );
    expect(noRequest).not.toHaveBeenCalled();
  });

  it("uses secure browser entropy when randomUUID is unavailable", async () => {
    const original = globalThis.crypto;
    Object.defineProperty(globalThis, "crypto", {
      configurable: true,
      value: { getRandomValues: (bytes: Uint8Array) => bytes.fill(9) },
    });
    try {
      const api = createAcornFoxClient(fetcher);
      await api.createApp({
        name: "A",
        repositoryUrl: "https://github.com/acme/a.git",
        ref: "main",
      });
      const header = new Headers(seen.at(-1)?.init.headers).get(
        "Idempotency-Key",
      );
      expect(header).toBe("09090909090909090909090909090909");
    } finally {
      Object.defineProperty(globalThis, "crypto", {
        configurable: true,
        value: original,
      });
    }
  });

  it("rejects extra fields and invalid schema facts across clean reads", async () => {
    const badReads = createAcornFoxClient(async (input) => {
      const url = String(input);
      if (url.includes("/sources/"))
        return json({
          id: "s",
          application_id: "a",
          kind: "git_https",
          locator_sha256: "x",
          content_digest: "y",
          created_at: "not-a-date",
          immutable: true,
          leaked: true,
        });
      if (url.includes("/logs?"))
        return json({
          source: "build",
          availability: "available",
          items: [
            {
              stream: "stdout",
              recorded_at: "not-a-date",
              content: "x",
              truncation: "complete",
            },
          ],
          next_cursor: null,
          retention_limited: false,
        });
      if (url.endsWith("/public-access"))
        return json({
          desired_public: false,
          url: "not-a-uri",
          endpoint: { deployment_id: "d" },
          components: {
            internal_endpoint: "accepted",
            local_route: "disabled",
            dns: "not_validated",
            tls: "not_validated",
            external: "not_validated",
          },
          status: "PUBLIC_DISABLED",
          extra: true,
        });
      return json({
        deployment: {
          id: "d",
          application_id: "a",
          environment_id: "e",
          release_id: "r",
          stage: "starting",
          created_at: "not-a-date",
          updated_at: "2026-01-01T00:00:00Z",
        },
        desired: null,
        runtime: null,
        response: null,
      });
    });
    await expect(badReads.source("a", "s")).rejects.toMatchObject({
      code: "invalid_response",
    });
    await expect(badReads.logs("a", "d", "build")).rejects.toMatchObject({
      code: "invalid_response",
    });
    await expect(badReads.publicAccess("a", "d")).rejects.toMatchObject({
      code: "invalid_response",
    });
    await expect(badReads.status("a", "d")).rejects.toMatchObject({
      code: "invalid_response",
    });
  });

  it("rejects extra fields on the application list and creation response", async () => {
    const extra = createAcornFoxClient(async (_input, init) =>
      init?.method === "POST"
        ? json(
            {
              application: {
                id: "a",
                name: "A",
                created_at: "2026-01-01T00:00:00Z",
                updated_at: "2026-01-01T00:00:00Z",
              },
              source_revision_id: "s",
              operation_id: "o",
              extra: true,
            },
            201,
          )
        : json({ items: [], extra: true }),
    );
    await expect(extra.apps()).rejects.toMatchObject({
      code: "invalid_response",
    });
    await expect(
      extra.createApp({
        name: "A",
        repositoryUrl: "https://github.com/acme/a.git",
        ref: "main",
      }),
    ).rejects.toMatchObject({ code: "invalid_response" });
  });

  it("accepts only the OpenAPI success status for every route class", async () => {
    for (const [path, method, status] of [
      ["/auth/login", "POST", 200],
      ["/auth/session", "GET", 200],
      ["/auth/logout", "POST", 204],
      ["/auth/password", "POST", 204],
      ["/apps", "GET", 200],
      ["/apps", "POST", 201],
      ["/apps/a", "GET", 200],
      ["/apps/a/sources", "GET", 200],
      ["/apps/a/sources/s", "GET", 200],
      ["/apps/a/deliveries", "GET", 200],
      ["/apps/a/deliveries", "POST", 202],
      ["/apps/a/deliveries/d", "GET", 200],
      ["/apps/a/deliveries/d/logs", "GET", 200],
      ["/apps/a/deliveries/d/restart", "POST", 202],
      ["/apps/a/deliveries/d/redeploy", "POST", 202],
      ["/apps/a/deliveries/d/public-access", "GET", 200],
      ["/apps/a/deliveries/d/public-access", "PUT", 200],
    ] as const)
      expect(expectedSuccessStatus(path, method)).toBe(status);
    const mismatch = createAcornFoxClient(async () =>
      json(
        {
          authenticated: true,
          idle_expires_at: "2026-01-01T00:00:00Z",
          absolute_expires_at: "2026-01-02T00:00:00Z",
        },
        201,
      ),
    );
    await expect(mismatch.session()).rejects.toMatchObject({
      code: "invalid_response",
    });
    const wrongCommand = createAcornFoxClient(async () =>
      json(
        {
          deployment_id: "d",
          operation_id: "o",
          task_id: "t",
          status: "accepted",
        },
        200,
      ),
    );
    await expect(wrongCommand.deploy("a", "s")).rejects.toMatchObject({
      code: "invalid_response",
    });
  });

  it("preserves opaque discovery and log page envelopes across 51 records", async () => {
    const sourceItem = (id: string) => ({
      id,
      application_id: "a",
      kind: "git_https",
      locator_sha256: "x",
      content_digest: "y",
      created_at: "2026-01-01T00:00:00Z",
      immutable: true,
    });
    const paged = createAcornFoxClient(async (input) => {
      const url = String(input);
      if (url.includes("/sources"))
        return json(
          url.includes("cursor=opaque-next")
            ? { items: [sourceItem("s-51")], next_cursor: null }
            : {
                items: Array.from({ length: 50 }, (_, index) =>
                  sourceItem(`s-${index + 1}`),
                ),
                next_cursor: "opaque-next",
              },
        );
      return json(
        url.includes("cursor=opaque-log")
          ? {
              source: "build",
              availability: "available",
              items: [],
              next_cursor: null,
              retention_limited: false,
            }
          : {
              source: "build",
              availability: "available",
              items: [],
              next_cursor: "opaque-log",
              retention_limited: false,
            },
      );
    });
    const first = await paged.sources("a");
    const second = await paged.sources("a", first.nextCursor);
    expect([...first.items, ...second.items]).toHaveLength(51);
    const logs = await paged.logs("a", "d", "build");
    expect(logs.nextCursor).toBe("opaque-log");
    await paged.logs("a", "d", "build", logs.nextCursor);
  });

  it("rejects public access URLs without HTTPS host-only authority", async () => {
    for (const value of [
      "http://example.test",
      "data:text/plain,no",
      "ftp://example.test",
      "https://user@example.test",
      "https://",
    ]) {
      const api = createAcornFoxClient(async () =>
        json({
          desired_public: false,
          url: value,
          endpoint: { deployment_id: "d" },
          components: {
            internal_endpoint: "accepted",
            local_route: "disabled",
            dns: "not_validated",
            tls: "not_validated",
            external: "not_validated",
          },
          status: "PUBLIC_DISABLED",
        }),
      );
      await expect(api.publicAccess("a", "d")).rejects.toMatchObject({
        code: "invalid_response",
      });
    }
  });
});
