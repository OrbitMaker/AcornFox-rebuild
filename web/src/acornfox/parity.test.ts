import { readFileSync } from "node:fs";
import { createAcornFoxClient, type AcornFoxClient } from "./client";
import { createAcornFoxIntegrationClient, type AcornFoxIntegrationClient } from "./integration-client";
import { createAcornFoxAssistantClient, type AcornFoxAssistantClient } from "./assistant-client";

type Operation = {
  operationId: string;
  method: string;
  pathTemplate: string;
  successStatuses: number[];
  proof:
    | "anonymous-login"
    | "anonymous-setup-read"
    | "anonymous-setup-mutation"
    | "session-read"
    | "csrf-session-mutation"
    | "csrf-idempotency-mutation";
  parity: "legacy_cli" | "integration_cli" | "integration_ui" | "assistant_ui_only" | "cli_only";
  cli: boolean;
  webClient: "legacy" | "integration" | "assistant" | "none";
};
type Matrix = {
  sourceRequestType: "public_git";
  sourceRevisionKind: "git_https";
  operations: Operation[];
};

const matrixPath = process.env.ACORNFOX_PARITY_MATRIX;
const matrix: Matrix | undefined = matrixPath
  ? (JSON.parse(readFileSync(matrixPath, "utf8")) as Matrix)
  : undefined;

const session = {
  authenticated: true,
  idle_expires_at: "2030-01-01T00:00:00Z",
  absolute_expires_at: "2030-01-02T00:00:00Z",
};
const application = {
  id: "app",
  name: "App",
  created_at: "2030-01-01T00:00:00Z",
  updated_at: "2030-01-01T00:00:00Z",
};
const command = {
  deployment_id: "deployment",
  operation_id: "operation",
  task_id: "task",
  status: "accepted",
};
const deployment = {
  id: "deployment",
  application_id: "app",
  environment_id: "environment",
  release_id: "release",
  stage: "starting",
  created_at: "2030-01-01T00:00:00Z",
  updated_at: "2030-01-01T00:00:00Z",
};

function payload(operationId: string, sourceRevisionKind: string): unknown {
  switch (operationId) {
    case "getAcornFoxSetupState":
      return { state: "uninitialized" };
    case "initializeAcornFoxAdministrator":
      return { initialized: true };
    case "loginAcornFoxAdministrator":
    case "getAcornFoxAdministratorSession":
      return session;
    case "logoutAcornFoxAdministrator":
    case "rotateAcornFoxAdministratorPassword":
      return undefined;
    case "listAcornFoxApps":
      return { items: [] };
    case "createAcornFoxApp":
      return { application, source_revision_id: "source", operation_id: "operation" };
    case "getAcornFoxApp":
      return application;
    case "listAcornFoxSourceRevisions":
      return { items: [], next_cursor: null };
    case "getAcornFoxSourceRevision":
      return { id: "source", application_id: "app", kind: sourceRevisionKind, locator_sha256: "sha256:locator", content_digest: "sha256:content", created_at: "2030-01-01T00:00:00Z", immutable: true };
    case "listAcornFoxDeliveries":
      return { items: [], next_cursor: null };
    case "createAcornFoxDelivery":
    case "probeAcornFoxDeliveryOnce":
    case "restartAcornFoxDelivery":
    case "redeployAcornFoxDelivery":
      return command;
    case "getAcornFoxDeliveryStatus":
      return { deployment, desired: null, runtime: null, response: null };
    case "listAcornFoxDeliveryLogs":
      return { source: "runtime", availability: "available", items: [], next_cursor: null, retention_limited: false };
    case "getAcornFoxDeliveryPublicAccess":
    case "setAcornFoxDeliveryPublicAccess":
      return { desired_public: true, url: "https://app.example.test", endpoint: { deployment_id: "deployment" }, components: { internal_endpoint: "accepted", local_route: "desired", dns: "not_validated", tls: "not_validated", external: "not_validated" }, status: "PENDING_EXTERNAL_VALIDATION" };
    case "getAcornFoxHostMetrics":
      return { schema_version: 1, availability: "warming_up", observed_at: "2030-01-01T00:00:00Z", stale_after_seconds: 15, cpu: { logical_cores: 4 }, memory: { total_bytes: 4096, available_bytes: 1024, used_bytes: 3072 }, disk: { mountpoint: "/", total_bytes: 8192, free_bytes: 4096, used_bytes: 4096 } };
    case "getAcornFoxSourceMetadata":
      return { source_revision_id: "source", availability: "unavailable" };
    case "updateAcornFoxSourceRevision":
      return { source_revision_id: "source-next", status: "imported" };
    case "getAcornFoxDeliverySource":
      return { deployment_id: "deployment", availability: "unavailable" };
    case "getAcornFoxOperationResult":
      return { operation_id: "operation", operation_type: "observe", status: "verified", task_id: "task", deployment_id: "deployment", accepted_at: "2030-01-01T00:00:00Z", updated_at: "2030-01-01T00:00:01Z", evidence: { kind: "response_observation", verdict: "unhealthy", observed_at: "2030-01-01T00:00:01Z", http_status: 500 } };
    case "getAcornFoxExternalAccessObservation":
      return { availability: "not_observed" };
    case "listAcornFoxAssistantSessions":
      return { sessions: [] };
    case "createAcornFoxAssistantSession":
      return { session_id: "session", scope: { kind: "host" }, created_at: "2030-01-01T00:00:00Z", updated_at: "2030-01-01T00:00:00Z" };
    case "submitAcornFoxAssistantRun":
      return { run: { run_id: "run", session_id: "session", status: "accepted", created_at: "2030-01-01T00:00:00Z", updated_at: "2030-01-01T00:00:00Z" }, replay: false };
    case "getAcornFoxAssistantEvents":
      return { status: "ok", oldest_cursor: 0, latest_cursor: 0, events: [] };
    case "abortAcornFoxAssistantSessionRuns":
      return { aborted: 0 };
    case "listAcornFoxAssistantActions":
      return { actions: [] };
    case "decideAcornFoxAssistantAction":
      return { proposal_id: "proposal", session_id: "session", run_id: "run", action: "restart", target: { application_id: "app", deployment_id: "deployment", target_release_id: "release", target_release_version: 1, application_name: "App" }, state: "accepted", expires_at: "2030-01-01T00:10:00Z", operation_id: "operation", verification: { state: "pending" }, created_at: "2030-01-01T00:00:00Z", updated_at: "2030-01-01T00:00:01Z" };
    default:
      throw new Error(`missing test payload for ${operationId}`);
  }
}

type WebOperation = {
  operationId: string;
  method: string;
  pathTemplate: string;
  invoke: (api: AcornFoxClient) => Promise<unknown>;
};
type IntegrationOperation = {
  operationId: string;
  method: string;
  pathTemplate: string;
  invoke: (api: AcornFoxIntegrationClient) => Promise<unknown>;
};
type AssistantOperation = {
  operationId: string;
  method: string;
  pathTemplate: string;
  invoke: (api: AcornFoxAssistantClient) => Promise<unknown>;
};

const webOperations: WebOperation[] = [
  { operationId: "loginAcornFoxAdministrator", method: "POST", pathTemplate: "/api/v1/acornfox/auth/login", invoke: (api) => api.login("secret") },
  { operationId: "logoutAcornFoxAdministrator", method: "POST", pathTemplate: "/api/v1/acornfox/auth/logout", invoke: (api) => api.logout() },
  { operationId: "getAcornFoxAdministratorSession", method: "GET", pathTemplate: "/api/v1/acornfox/auth/session", invoke: (api) => api.session() },
  { operationId: "rotateAcornFoxAdministratorPassword", method: "POST", pathTemplate: "/api/v1/acornfox/auth/password", invoke: (api) => api.changePassword("old", "new") },
  { operationId: "listAcornFoxApps", method: "GET", pathTemplate: "/api/v1/acornfox/apps", invoke: (api) => api.apps() },
  { operationId: "createAcornFoxApp", method: "POST", pathTemplate: "/api/v1/acornfox/apps", invoke: (api) => api.createApp({ name: "App", repositoryUrl: "https://github.com/acme/app.git", ref: "main" }) },
  { operationId: "getAcornFoxApp", method: "GET", pathTemplate: "/api/v1/acornfox/apps/{applicationId}", invoke: (api) => api.app("app") },
  { operationId: "listAcornFoxSourceRevisions", method: "GET", pathTemplate: "/api/v1/acornfox/apps/{applicationId}/sources", invoke: (api) => api.sources("app") },
  { operationId: "getAcornFoxSourceRevision", method: "GET", pathTemplate: "/api/v1/acornfox/apps/{applicationId}/sources/{sourceRevisionId}", invoke: (api) => api.source("app", "source") },
  { operationId: "listAcornFoxDeliveries", method: "GET", pathTemplate: "/api/v1/acornfox/apps/{applicationId}/deliveries", invoke: (api) => api.deployments("app") },
  { operationId: "createAcornFoxDelivery", method: "POST", pathTemplate: "/api/v1/acornfox/apps/{applicationId}/deliveries", invoke: (api) => api.deploy("app", "source") },
  { operationId: "getAcornFoxDeliveryStatus", method: "GET", pathTemplate: "/api/v1/acornfox/apps/{applicationId}/deliveries/{deploymentId}", invoke: (api) => api.status("app", "deployment") },
  { operationId: "listAcornFoxDeliveryLogs", method: "GET", pathTemplate: "/api/v1/acornfox/apps/{applicationId}/deliveries/{deploymentId}/logs", invoke: (api) => api.logs("app", "deployment", "runtime") },
  { operationId: "probeAcornFoxDeliveryOnce", method: "POST", pathTemplate: "/api/v1/acornfox/apps/{applicationId}/deliveries/{deploymentId}/probes", invoke: (api) => api.probe("app", "deployment") },
  { operationId: "restartAcornFoxDelivery", method: "POST", pathTemplate: "/api/v1/acornfox/apps/{applicationId}/deliveries/{deploymentId}/restart", invoke: (api) => api.restart("app", "deployment") },
  { operationId: "redeployAcornFoxDelivery", method: "POST", pathTemplate: "/api/v1/acornfox/apps/{applicationId}/deliveries/{deploymentId}/redeploy", invoke: (api) => api.redeploy("app", "deployment") },
  { operationId: "getAcornFoxDeliveryPublicAccess", method: "GET", pathTemplate: "/api/v1/acornfox/apps/{applicationId}/deliveries/{deploymentId}/public-access", invoke: (api) => api.publicAccess("app", "deployment") },
  { operationId: "setAcornFoxDeliveryPublicAccess", method: "PUT", pathTemplate: "/api/v1/acornfox/apps/{applicationId}/deliveries/{deploymentId}/public-access", invoke: (api) => api.setPublicAccess("app", "deployment", true) },
];
const integrationOperations: IntegrationOperation[] = [
  { operationId: "getAcornFoxSetupState", method: "GET", pathTemplate: "/api/v1/acornfox/setup", invoke: (api) => api.setupState() },
  { operationId: "initializeAcornFoxAdministrator", method: "POST", pathTemplate: "/api/v1/acornfox/setup", invoke: (api) => api.setup({ setupToken: "single-use", password: "not-a-real-password" }) },
  { operationId: "getAcornFoxHostMetrics", method: "GET", pathTemplate: "/api/v1/acornfox/host/metrics", invoke: (api) => api.hostMetrics() },
  { operationId: "getAcornFoxSourceMetadata", method: "GET", pathTemplate: "/api/v1/acornfox/apps/{applicationId}/sources/{sourceRevisionId}/metadata", invoke: (api) => api.sourceMetadata("app", "source") },
  { operationId: "updateAcornFoxSourceRevision", method: "POST", pathTemplate: "/api/v1/acornfox/apps/{applicationId}/sources", invoke: (api) => api.sourceUpdate("app", { baseSourceRevisionId: "source", ref: "main" }, "retry-key") },
  { operationId: "getAcornFoxDeliverySource", method: "GET", pathTemplate: "/api/v1/acornfox/apps/{applicationId}/deliveries/{deploymentId}/source", invoke: (api) => api.deploymentSource("app", "deployment") },
  { operationId: "getAcornFoxOperationResult", method: "GET", pathTemplate: "/api/v1/acornfox/apps/{applicationId}/operations/{operationId}", invoke: (api) => api.operationResult("app", "operation") },
  { operationId: "getAcornFoxExternalAccessObservation", method: "GET", pathTemplate: "/api/v1/acornfox/apps/{applicationId}/deliveries/{deploymentId}/access-observation", invoke: (api) => api.accessObservation("app", "deployment") },
];
const assistantOperations: AssistantOperation[] = [
  { operationId: "listAcornFoxAssistantSessions", method: "GET", pathTemplate: "/api/v1/acornfox/assistant/sessions", invoke: (api) => api.sessions() },
  { operationId: "createAcornFoxAssistantSession", method: "POST", pathTemplate: "/api/v1/acornfox/assistant/sessions", invoke: (api) => api.createSession({ kind: "host" }) },
  { operationId: "submitAcornFoxAssistantRun", method: "POST", pathTemplate: "/api/v1/acornfox/assistant/sessions/{sessionId}/runs", invoke: (api) => api.submitRun("session", "show host facts", "retry-key") },
  { operationId: "getAcornFoxAssistantEvents", method: "GET", pathTemplate: "/api/v1/acornfox/assistant/sessions/{sessionId}/events", invoke: (api) => api.events("session", 0) },
  { operationId: "abortAcornFoxAssistantSessionRuns", method: "POST", pathTemplate: "/api/v1/acornfox/assistant/sessions/{sessionId}/abort", invoke: (api) => api.abort("session") },
  { operationId: "listAcornFoxAssistantActions", method: "GET", pathTemplate: "/api/v1/acornfox/assistant/sessions/{sessionId}/actions", invoke: (api) => api.actions("session") },
  { operationId: "decideAcornFoxAssistantAction", method: "POST", pathTemplate: "/api/v1/acornfox/assistant/sessions/{sessionId}/actions/{proposalId}/decision", invoke: (api) => api.decideAction("session", "proposal", true) },
];

function actualTemplate(url: string, expected: string): string {
  const pathname = new URL(url, "https://acornfox.invalid").pathname;
  const actual = pathname.split("/");
  const template = expected.split("/");
  if (actual.length !== template.length) return pathname;
  return template.map((part, index) => (/^\{.+\}$/.test(part) ? part : actual[index])).join("/");
}

describe("AcornFox OpenAPI parity", () => {
  it.skipIf(!matrix)("derives legacy-client coverage, status, and proof from fresh OpenAPI", async () => {
    const contract = matrix!;
    expect(contract.sourceRequestType).toBe("public_git");
    expect(contract.sourceRevisionKind).toBe("git_https");
    const legacy = contract.operations.filter((operation) => operation.webClient === "legacy");
    expect(webOperations).toHaveLength(legacy.length);
    const contractByID = new Map(legacy.map((operation) => [operation.operationId, operation]));

    for (const declared of webOperations) {
      const operation = contractByID.get(declared.operationId);
      expect(operation).toBeDefined();
      expect(declared.method).toBe(operation!.method);
      expect(declared.pathTemplate).toBe(operation!.pathTemplate);
      const seen: { url: string; init: RequestInit }[] = [];
      Object.defineProperty(globalThis, "document", { configurable: true, value: { cookie: "__Host-acornfox_csrf=csrf" } });
      const api = createAcornFoxClient(async (input, init) => {
        seen.push({ url: String(input), init: init ?? {} });
        const body = payload(declared.operationId, contract.sourceRevisionKind);
        return body === undefined
          ? new Response(null, { status: operation!.successStatuses[0] })
          : new Response(JSON.stringify(body), { status: operation!.successStatuses[0], headers: { "Content-Type": "application/json" } });
      });
      await declared.invoke(api);
      expect(seen).toHaveLength(1);
      const request = seen[0]!;
      expect(actualTemplate(request.url, declared.pathTemplate)).toBe(operation!.pathTemplate);
      expect((request.init.method ?? "GET").toUpperCase()).toBe(operation!.method);
      expect(request.init.credentials).toBe("include");
      const headers = new Headers(request.init.headers);
      const hasCSRF = headers.get("X-AcornFox-CSRF") === "csrf";
      const hasKey = headers.get("Idempotency-Key") !== null;
      expect({
        "anonymous-login": [false, false],
        "anonymous-setup-read": [false, false],
        "anonymous-setup-mutation": [true, false],
        "session-read": [false, false],
        "csrf-session-mutation": [true, false],
        "csrf-idempotency-mutation": [true, true],
      }[operation!.proof]).toEqual([hasCSRF, hasKey]);
      if (declared.operationId === "createAcornFoxApp") {
        const body = JSON.parse(String(request.init.body)) as { source: { type: string } };
        expect(body.source.type).toBe(contract.sourceRequestType);
      }
    }
  });

  it.skipIf(!matrix)("derives integration-client coverage, status, and proof from fresh OpenAPI", async () => {
    const contract = matrix!;
    const integration = contract.operations.filter((operation) => operation.webClient === "integration");
    expect(integration.map((operation) => operation.operationId).sort()).toEqual([
      "getAcornFoxDeliverySource", "getAcornFoxExternalAccessObservation", "getAcornFoxHostMetrics", "getAcornFoxOperationResult", "getAcornFoxSetupState", "getAcornFoxSourceMetadata", "initializeAcornFoxAdministrator", "updateAcornFoxSourceRevision",
    ]);
    expect(integrationOperations).toHaveLength(integration.length);
    expect(contract.operations.filter((operation) => operation.webClient === "none").map((operation) => operation.operationId)).toEqual(["createAcornFoxFixCandidate", "getAcornFoxFixCandidate", "listAcornFoxFixCandidates", "matchAcornFoxFixCandidateSource", "publishAcornFoxFixCandidate", "reportAcornFoxExternalAccessObservation"]);
    const contractByID = new Map(integration.map((operation) => [operation.operationId, operation]));

    for (const declared of integrationOperations) {
      const operation = contractByID.get(declared.operationId);
      expect(operation).toBeDefined();
      expect(declared.method).toBe(operation!.method);
      expect(declared.pathTemplate).toBe(operation!.pathTemplate);
      const seen: { url: string; init: RequestInit }[] = [];
      Object.defineProperty(globalThis, "document", { configurable: true, value: { cookie: "__Host-acornfox_csrf=csrf" } });
      const api = createAcornFoxIntegrationClient(async (input, init) => {
        seen.push({ url: String(input), init: init ?? {} });
        const body = payload(declared.operationId, contract.sourceRevisionKind);
        return new Response(JSON.stringify(body), { status: operation!.successStatuses[0], headers: { "Content-Type": "application/json" } });
      });
      await declared.invoke(api);
      expect(seen).toHaveLength(1);
      const request = seen[0]!;
      expect(actualTemplate(request.url, declared.pathTemplate)).toBe(operation!.pathTemplate);
      expect((request.init.method ?? "GET").toUpperCase()).toBe(operation!.method);
      expect(request.init.credentials).toBe("include");
      const headers = new Headers(request.init.headers);
      const hasCSRF = headers.get("X-AcornFox-CSRF") === "csrf";
      const hasKey = headers.get("Idempotency-Key") !== null;
      expect({
        "anonymous-setup-read": [false, false],
        "anonymous-setup-mutation": [true, false],
        "anonymous-login": [false, false],
        "session-read": [false, false],
        "csrf-session-mutation": [true, false],
        "csrf-idempotency-mutation": [true, true],
      }[operation!.proof]).toEqual([hasCSRF, hasKey]);
    }
  });

  it.skipIf(!matrix)("derives assistant-client coverage, status, and proof from fresh OpenAPI", async () => {
    const contract = matrix!;
    const assistant = contract.operations.filter((operation) => operation.webClient === "assistant");
    expect(assistant.map((operation) => operation.operationId).sort()).toEqual([
      "abortAcornFoxAssistantSessionRuns", "createAcornFoxAssistantSession", "decideAcornFoxAssistantAction", "getAcornFoxAssistantEvents", "listAcornFoxAssistantActions", "listAcornFoxAssistantSessions", "submitAcornFoxAssistantRun",
    ]);
    expect(assistantOperations).toHaveLength(assistant.length);
    const contractByID = new Map(assistant.map((operation) => [operation.operationId, operation]));

    for (const declared of assistantOperations) {
      const operation = contractByID.get(declared.operationId);
      expect(operation).toBeDefined();
      expect(declared.method).toBe(operation!.method);
      expect(declared.pathTemplate).toBe(operation!.pathTemplate);
      const seen: { url: string; init: RequestInit }[] = [];
      Object.defineProperty(globalThis, "document", { configurable: true, value: { cookie: "__Host-acornfox_csrf=csrf" } });
      const api = createAcornFoxAssistantClient(async (input, init) => {
        seen.push({ url: String(input), init: init ?? {} });
        const body = payload(declared.operationId, contract.sourceRevisionKind);
        const status = declared.operationId === "submitAcornFoxAssistantRun" || declared.operationId === "decideAcornFoxAssistantAction" ? 202 : operation!.successStatuses[0]!;
        expect(operation!.successStatuses).toContain(status);
        return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
      });
      await declared.invoke(api);
      expect(seen).toHaveLength(1);
      const request = seen[0]!;
      expect(actualTemplate(request.url, declared.pathTemplate)).toBe(operation!.pathTemplate);
      expect((request.init.method ?? "GET").toUpperCase()).toBe(operation!.method);
      expect(request.init.credentials).toBe("include");
      const headers = new Headers(request.init.headers);
      const hasCSRF = headers.get("X-AcornFox-CSRF") === "csrf";
      expect({
        "session-read": false,
        "csrf-session-mutation": true,
        "anonymous-login": false,
        "anonymous-setup-read": false,
        "anonymous-setup-mutation": true,
        "csrf-idempotency-mutation": true,
      }[operation!.proof]).toBe(hasCSRF);
    }
  });
});
