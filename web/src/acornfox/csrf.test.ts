import { describe, expect, it, beforeEach, afterEach } from "vitest";
import {
  EXACT_LOCAL_ORIGIN,
  LOCAL_CSRF_COOKIE_NAME,
  PUBLIC_CSRF_COOKIE_NAME,
  resolveCsrfToken,
} from "./csrf";
import { createAcornFoxClient } from "./client";
import { createAcornFoxIntegrationClient } from "./integration-client";
import { createAcornFoxAssistantClient } from "./assistant-client";
import { createFixCandidateClient } from "./fix-candidate-client";

describe("resolveCsrfToken", () => {
  it("resolves public cookie on HTTPS public origin", () => {
    const doc = {
      cookie: `${PUBLIC_CSRF_COOKIE_NAME}=public_secret_123; other=val`,
    };
    const loc = { origin: "https://console.example.com" };
    expect(resolveCsrfToken(doc, loc)).toBe("public_secret_123");
  });

  it("does not fall back to local cookie on public origin even if present", () => {
    const doc = {
      cookie: `${LOCAL_CSRF_COOKIE_NAME}=local_secret_456; other=val`,
    };
    const loc = { origin: "https://console.example.com" };
    expect(resolveCsrfToken(doc, loc)).toBeUndefined();
  });

  it("resolves local cookie when origin is exact 127.0.0.1:8080", () => {
    const doc = {
      cookie: `${LOCAL_CSRF_COOKIE_NAME}=local_secret_456; other=val`,
    };
    const loc = { origin: EXACT_LOCAL_ORIGIN };
    expect(resolveCsrfToken(doc, loc)).toBe("local_secret_456");
  });

  it("does not resolve public cookie on exact local origin if local cookie missing", () => {
    const doc = {
      cookie: `${PUBLIC_CSRF_COOKIE_NAME}=public_secret_123; other=val`,
    };
    const loc = { origin: EXACT_LOCAL_ORIGIN };
    expect(resolveCsrfToken(doc, loc)).toBeUndefined();
  });

  it("treats non-exact local addresses (localhost, 127.0.0.2, other port) as non-local", () => {
    const doc = {
      cookie: `${LOCAL_CSRF_COOKIE_NAME}=local_secret; ${PUBLIC_CSRF_COOKIE_NAME}=public_secret`,
    };
    expect(resolveCsrfToken(doc, { origin: "http://localhost:8080" })).toBe(
      "public_secret",
    );
    expect(resolveCsrfToken(doc, { origin: "http://127.0.0.2:8080" })).toBe(
      "public_secret",
    );
    expect(resolveCsrfToken(doc, { origin: "http://127.0.0.1:3000" })).toBe(
      "public_secret",
    );
  });

  it("returns undefined when document is missing or cookie empty", () => {
    expect(resolveCsrfToken(undefined, { origin: EXACT_LOCAL_ORIGIN })).toBeUndefined();
    expect(resolveCsrfToken({ cookie: "" }, { origin: EXACT_LOCAL_ORIGIN })).toBeUndefined();
  });
});

describe("All 4 Web clients dispatch local CSRF header under local-origin", () => {
  const origDoc = (globalThis as any).document;
  const origWin = (globalThis as any).window;

  beforeEach(() => {
    (globalThis as any).document = {
      cookie: `${LOCAL_CSRF_COOKIE_NAME}=local_test_csrf_token_888`,
    };
    (globalThis as any).window = {
      location: { origin: EXACT_LOCAL_ORIGIN },
    };
  });

  afterEach(() => {
    (globalThis as any).document = origDoc;
    (globalThis as any).window = origWin;
  });

  it("client.ts dispatches local CSRF header on POST", async () => {
    let capturedHeader: string | null = null;
    const fetcher = async (input: RequestInfo | URL, init?: RequestInit) => {
      const headers = new Headers(init?.headers);
      capturedHeader = headers.get("X-AcornFox-CSRF");
      return new Response(null, { status: 204 });
    };
    const client = createAcornFoxClient(fetcher);
    await client.logout();
    expect(capturedHeader).toBe("local_test_csrf_token_888");
  });

  it("integration-client.ts dispatches local CSRF header on POST", async () => {
    let capturedHeader: string | null = null;
    const fetcher = async (input: RequestInfo | URL, init?: RequestInit) => {
      const headers = new Headers(init?.headers);
      capturedHeader = headers.get("X-AcornFox-CSRF");
      return new Response(JSON.stringify({ initialized: true }), {
        status: 201,
        headers: { "Content-Type": "application/json" },
      });
    };
    const client = createAcornFoxIntegrationClient(fetcher);
    await client.setup({ setupToken: "tok", password: "pwd" });
    expect(capturedHeader).toBe("local_test_csrf_token_888");
  });

  it("assistant-client.ts dispatches local CSRF header on POST", async () => {
    let capturedHeader: string | null = null;
    const fetcher = async (input: RequestInfo | URL, init?: RequestInit) => {
      const headers = new Headers(init?.headers);
      capturedHeader = headers.get("X-AcornFox-CSRF");
      return new Response(
        JSON.stringify({
          session_id: "s1",
          scope: { kind: "host" },
          created_at: "2026-01-01T00:00:00Z",
          updated_at: "2026-01-01T00:00:00Z",
        }),
        { status: 201, headers: { "Content-Type": "application/json" } },
      );
    };
    const client = createAcornFoxAssistantClient(fetcher);
    await client.createSession({ kind: "host" });
    expect(capturedHeader).toBe("local_test_csrf_token_888");
  });

  it("fix-candidate-client.ts dispatches local CSRF header on POST", async () => {
    let capturedHeader: string | null = null;
    const fetcher = async (input: RequestInfo | URL, init?: RequestInit) => {
      const headers = new Headers(init?.headers);
      capturedHeader = headers.get("X-AcornFox-CSRF");
      return new Response(
        JSON.stringify({
          deployment_id: "d1",
          operation_id: "op1",
          task_id: "t1",
          status: "accepted",
        }),
        { status: 202, headers: { "Content-Type": "application/json" } },
      );
    };
    const client = createFixCandidateClient(fetcher);
    await client.publish("app1", "c1", "key1");
    expect(capturedHeader).toBe("local_test_csrf_token_888");
  });
});
