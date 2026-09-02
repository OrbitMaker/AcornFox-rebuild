import { readFileSync } from "node:fs";
import { createAcornFoxClient, type AcornFoxClient } from "./client";

type Operation = {
  operationId: string;
  method: string;
  pathTemplate: string;
  successStatus: number;
  proof:
    | "anonymous-login"
    | "session-read"
    | "csrf-session-mutation"
    | "csrf-idempotency-mutation";
  visible: boolean;
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
  { operationId: "restartAcornFoxDelivery", method: "POST", pathTemplate: "/api/v1/acornfox/apps/{applicationId}/deliveries/{deploymentId}/restart", invoke: (api) => api.restart("app", "deployment") },
  { operationId: "redeployAcornFoxDelivery", method: "POST", pathTemplate: "/api/v1/acornfox/apps/{applicationId}/deliveries/{deploymentId}/redeploy", invoke: (api) => api.redeploy("app", "deployment") },
  { operationId: "getAcornFoxDeliveryPublicAccess", method: "GET", pathTemplate: "/api/v1/acornfox/apps/{applicationId}/deliveries/{deploymentId}/public-access", invoke: (api) => api.publicAccess("app", "deployment") },
  { operationId: "setAcornFoxDeliveryPublicAccess", method: "PUT", pathTemplate: "/api/v1/acornfox/apps/{applicationId}/deliveries/{deploymentId}/public-access", invoke: (api) => api.setPublicAccess("app", "deployment", true) },
];

function actualTemplate(url: string, expected: string): string {
  const pathname = new URL(url, "https://acornfox.invalid").pathname;
  const actual = pathname.split("/");
  const template = expected.split("/");
  if (actual.length !== template.length) return pathname;
  return template.map((part, index) => (/^\{.+\}$/.test(part) ? part : actual[index])).join("/");
}

describe("AcornFox OpenAPI parity", () => {
  it.skipIf(!matrix)("derives visible Web coverage, status, and proof from fresh OpenAPI", async () => {
    const contract = matrix!;
    expect(contract.sourceRequestType).toBe("public_git");
    expect(contract.sourceRevisionKind).toBe("git_https");
    const visible = contract.operations.filter((operation) => operation.visible);
    expect(contract.operations.filter((operation) => !operation.visible)).toEqual([
      expect.objectContaining({ operationId: "probeAcornFoxDeliveryOnce" }),
    ]);
    expect(webOperations).toHaveLength(visible.length);
    const contractByID = new Map(visible.map((operation) => [operation.operationId, operation]));

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
          ? new Response(null, { status: operation!.successStatus })
          : new Response(JSON.stringify(body), { status: operation!.successStatus, headers: { "Content-Type": "application/json" } });
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
});
