import { readFileSync } from "node:fs";
import { createAcornFoxClient, type AcornFoxClient, type AcornFoxSchemas } from "./client";
import { createAcornFoxIntegrationClient, type AcornFoxIntegrationClient } from "./integration-client";
import { createAcornFoxAssistantClient, type AcornFoxAssistantClient } from "./assistant-client";
import { candidatePublishKey, createFixCandidateClient, type FixCandidateClient } from "./fix-candidate-client";
import { candidateFixture } from "./fix-candidate.fixture";

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
  parity: "legacy_cli" | "integration_cli" | "integration_ui" | "assistant_ui_only" | "candidate_cli" | "cli_only";
  cli: boolean;
  webClient: "legacy" | "integration" | "assistant" | "candidate" | "none";
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
    case "getAcornFoxDeploymentPlan":
      return { application_id: "app", source_revision_id: "source", repository_url: "https://github.com/example/app.git", ref: "main", commit: "a".repeat(40), dockerfile: { status: "ready", path: "Dockerfile", digest: `sha256:${"d".repeat(64)}`, stage_count: 1, final_stage: { name: "final", index: 0, from: "scratch" } }, ports: [{ port: 3000, protocol: "tcp", source: "dockerfile_expose" }], port_selection: { status: "selected", reason: "dockerfile_expose", selected_port: 3000, candidates: [3000] }, healthcheck: { present: false }, environment: [], gaps: [], warnings: [], required_actions: [], ready_to_deploy: true };
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
  { operationId: "getAcornFoxDeploymentPlan", method: "GET", pathTemplate: "/api/v1/acornfox/apps/{applicationId}/sources/{sourceRevisionId}/deployment-plan", invoke: (api) => api.deploymentPlan("app", "source") },
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

// These payloads also compile against the generated OpenAPI DTOs. Runtime
// assertions below invoke the actual candidate client and inspect its decoding.
const validatedCandidate = { ...candidateFixture, status: "validated" as const,
  runtime: { ...candidateFixture.runtime, runtime_state: "stopped" as const, probe_outcome: "responded" as const, cleanup_confirmed: true as const },
} satisfies AcornFoxSchemas["FixCandidateValidated"];
const matchedCandidate = { ...validatedCandidate, status: "source_matched" as const, matched_source_revision_id: "source-next", matched_commit: "9".repeat(40) } satisfies AcornFoxSchemas["FixCandidateValidated"];
const candidateID = candidateFixture.candidate_id, candidateApp = candidateFixture.application_id;
const publishKey = candidatePublishKey(candidateApp, candidateID);
const candidateRoot = "/api/v1/acornfox/apps/{applicationId}/fix-candidates";
const candidateOperations: Array<{
  operationId: string; method: string; pathTemplate: string; expectedURL: string;
  response: unknown; decoded: unknown; body?: unknown;
  invoke: (api: FixCandidateClient) => Promise<unknown>;
}> = [
  { operationId: "listAcornFoxFixCandidates", method: "GET", pathTemplate: candidateRoot, expectedURL: `/api/v1/acornfox/apps/${candidateApp}/fix-candidates`, response: { items: [validatedCandidate] } satisfies AcornFoxSchemas["FixCandidateList"], decoded: [validatedCandidate], invoke: (api) => api.list(candidateApp) },
  { operationId: "getAcornFoxFixCandidate", method: "GET", pathTemplate: `${candidateRoot}/{candidateId}`, expectedURL: `/api/v1/acornfox/apps/${candidateApp}/fix-candidates/${candidateID}`, response: validatedCandidate, decoded: validatedCandidate, invoke: (api) => api.get(candidateApp, candidateID) },
  { operationId: "matchAcornFoxFixCandidateSource", method: "POST", pathTemplate: `${candidateRoot}/{candidateId}/source-match`, expectedURL: `/api/v1/acornfox/apps/${candidateApp}/fix-candidates/${candidateID}/source-match`, response: matchedCandidate, decoded: matchedCandidate, body: { source_revision_id: "source-next" } satisfies AcornFoxSchemas["FixCandidateSourceMatchRequest"], invoke: (api) => api.match(candidateApp, candidateID, "source-next") },
  { operationId: "publishAcornFoxFixCandidate", method: "POST", pathTemplate: `${candidateRoot}/{candidateId}/publish`, expectedURL: `/api/v1/acornfox/apps/${candidateApp}/fix-candidates/${candidateID}/publish`, response: command satisfies AcornFoxSchemas["DeliveryCommandResponse"], decoded: command, invoke: (api) => api.publish(candidateApp, candidateID, publishKey) },
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
      "getAcornFoxDeliverySource", "getAcornFoxDeploymentPlan", "getAcornFoxExternalAccessObservation", "getAcornFoxHostMetrics", "getAcornFoxOperationResult", "getAcornFoxSetupState", "getAcornFoxSourceMetadata", "initializeAcornFoxAdministrator", "updateAcornFoxSourceRevision",
    ]);
    expect(integrationOperations).toHaveLength(integration.length);
    expect(contract.operations.filter((operation) => operation.webClient === "none").map((operation) => operation.operationId)).toEqual(["createAcornFoxFixCandidate", "reportAcornFoxExternalAccessObservation"]);
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

  it.skipIf(!matrix)("derives candidate Web coverage and invokes the real client for method, DTO, CSRF and replay-key parity", async () => {
    const declared = matrix!.operations.filter((operation) => operation.webClient === "candidate");
    expect(declared.map((operation) => operation.operationId).sort()).toEqual(candidateOperations.map((operation) => operation.operationId).sort());
    expect(matrix!.operations.filter((operation) => operation.webClient === "legacy")).toHaveLength(18);
    expect(matrix!.operations.find((operation) => operation.operationId === "createAcornFoxFixCandidate")).toMatchObject({ parity: "cli_only", cli: true, webClient: "none" });
    for (const route of candidateOperations) {
      const operation = declared.find((item) => item.operationId === route.operationId)!;
      expect(operation).toMatchObject({ parity: "candidate_cli", cli: true, method: route.method, pathTemplate: route.pathTemplate });
      Object.defineProperty(globalThis, "document", { configurable: true, value: { cookie: "__Host-acornfox_csrf=csrf" } });
      for (const status of operation.successStatuses) {
        const seen: Array<{ url: string; init: RequestInit }> = [];
        const api = createFixCandidateClient(async (url, init) => { seen.push({ url: String(url), init: init ?? {} }); return new Response(JSON.stringify(route.response), { status, headers: { "Content-Type": "application/json" } }); });
        await expect(route.invoke(api)).resolves.toEqual(route.decoded);
        expect(seen).toHaveLength(1);
        const request = seen[0]!;
        expect(request.url).toBe(route.expectedURL); expect(actualTemplate(request.url, route.pathTemplate)).toBe(operation.pathTemplate);
        expect(request.init.method ?? "GET").toBe(operation.method); expect(request.init).toMatchObject({ credentials: "include", redirect: "error" });
        const headers = new Headers(request.init.headers);
        expect({ "session-read": [false, false], "csrf-session-mutation": [true, false], "csrf-idempotency-mutation": [true, true] }[operation.proof as "session-read" | "csrf-session-mutation" | "csrf-idempotency-mutation"]).toEqual([headers.get("X-AcornFox-CSRF") === "csrf", headers.has("Idempotency-Key")]);
        expect(request.init.body === undefined ? undefined : JSON.parse(String(request.init.body))).toEqual(route.body);
        if (operation.operationId === "publishAcornFoxFixCandidate") expect(headers.get("Idempotency-Key")).toBe(publishKey);
      }
    }
  });

  it.skipIf(!matrix)("rejects wrong candidate response statuses and malformed DTOs instead of passing on route names alone", async () => {
    Object.defineProperty(globalThis, "document", { configurable: true, value: { cookie: "__Host-acornfox_csrf=csrf" } });
    for (const route of candidateOperations) {
      const operation = matrix!.operations.find((item) => item.operationId === route.operationId)!;
      const wrongStatus = operation.successStatuses.includes(200) ? 202 : 200;
      const wrongHTTP = createFixCandidateClient(async () => new Response(JSON.stringify(route.response), { status: wrongStatus, headers: { "Content-Type": "application/json" } }));
      await expect(route.invoke(wrongHTTP)).rejects.toMatchObject({ status: wrongStatus });
      const malformed = createFixCandidateClient(async () => new Response(JSON.stringify({ status: "validated" }), { status: operation.successStatuses[0], headers: { "Content-Type": "application/json" } }));
      await expect(route.invoke(malformed)).rejects.toMatchObject({ code: "invalid_response" });
      if (route.method === "POST") {
        Object.defineProperty(globalThis, "document", { configurable: true, value: { cookie: "" } });
        let calls = 0;
        const noSessionProof = createFixCandidateClient(async () => { calls += 1; return new Response(JSON.stringify(route.response), { status: operation.successStatuses[0] }); });
        await expect(route.invoke(noSessionProof)).rejects.toMatchObject({ code: "csrf_missing" }); expect(calls).toBe(0);
        Object.defineProperty(globalThis, "document", { configurable: true, value: { cookie: "__Host-acornfox_csrf=csrf" } });
      }
    }
  });

  it.skipIf(!matrix)("keeps the publication receipt key when a real candidate-client request loses its response", async () => {
    const operation = matrix!.operations.find((item) => item.operationId === "publishAcornFoxFixCandidate")!;
    expect(operation.proof).toBe("csrf-idempotency-mutation");
    Object.defineProperty(globalThis, "document", { configurable: true, value: { cookie: "__Host-acornfox_csrf=csrf" } });
    const seen: RequestInit[] = [];
    const fetcher = async (_url: RequestInfo | URL, init?: RequestInit) => {
      seen.push(init ?? {});
      if (seen.length === 1) throw new Error("accepted response was lost");
      return new Response(JSON.stringify(command), { status: operation.successStatuses[0], headers: { "Content-Type": "application/json" } });
    };
    await expect(createFixCandidateClient(fetcher).publish(candidateApp, candidateID, candidatePublishKey(candidateApp, candidateID))).rejects.toMatchObject({ code: "network_error" });
    await expect(createFixCandidateClient(fetcher).publish(candidateApp, candidateID, candidatePublishKey(candidateApp, candidateID))).resolves.toEqual(command);
    expect(seen).toHaveLength(2);
    expect(seen.map((request) => new Headers(request.headers).get("Idempotency-Key"))).toEqual([publishKey, publishKey]);
    expect(seen.map((request) => request.body)).toEqual([undefined, undefined]);
  });

});
