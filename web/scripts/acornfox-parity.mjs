import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { bundle, createConfig } from "@redocly/openapi-core";

const webRoot = resolve(fileURLToPath(new URL("..", import.meta.url)));
const repositoryRoot = resolve(webRoot, "..");
const schemaPath = resolve(repositoryRoot, "api/openapi/acornfox.yaml");
const vitestPath = resolve(webRoot, "node_modules", ".bin", "vitest");
const matrixDirectory = mkdtempSync(resolve(tmpdir(), "acornfox-parity-"));
const matrixPath = resolve(matrixDirectory, "matrix.json");

function fail(message) {
  throw new Error(`AcornFox OpenAPI parity: ${message}`);
}

function parameter(document, value) {
  if (value?.$ref) {
    const prefix = "#/components/parameters/";
    if (!value.$ref.startsWith(prefix)) fail(`unsupported parameter ref ${value.$ref}`);
    return document.components?.parameters?.[value.$ref.slice(prefix.length)];
  }
  return value;
}

function proofClass(document, pathItem, operation, method, operationId) {
  if (Array.isArray(operation.security) && operation.security.length === 0) {
    if (operationId === "loginAcornFoxAdministrator") return "anonymous-login";
    if (parityScope(operation, operationId) === "integration_ui") return method === "get" ? "anonymous-setup-read" : "anonymous-setup-mutation";
    if (operationId !== "loginAcornFoxAdministrator")
      fail(`${operationId} is anonymous but is not the login operation`);
  }
  if (
    !Array.isArray(operation.security) ||
    !operation.security.some(
      (requirement) => requirement && Object.hasOwn(requirement, "AdministratorSession"),
    )
  )
    fail(`${operationId} must require the administrator session`);
  if (method === "get") return "session-read";
  const parameters = [...(pathItem.parameters ?? []), ...(operation.parameters ?? [])]
    .map((item) => parameter(document, item));
  const names = new Set(parameters.map((item) => `${item?.in}:${item?.name}`));
  if (!names.has("header:X-AcornFox-CSRF"))
    fail(`${operationId} mutates a session without the CSRF parameter`);
  return names.has("header:Idempotency-Key")
    ? "csrf-idempotency-mutation"
    : "csrf-session-mutation";
}

function successStatuses(operation, operationId) {
  const statuses = Object.keys(operation.responses ?? {}).filter((status) => /^2\d\d$/.test(status));
  if (statuses.length === 0)
    fail(`${operationId} must declare a 2xx response`);
  return statuses.map(Number).sort((left, right) => left - right);
}

function parityScope(operation, operationId) {
  const scope = operation["x-acornfox-parity"] ?? "legacy_cli";
  if (!["legacy_cli", "integration_cli", "integration_ui", "assistant_ui_only", "candidate_cli", "cli_only"].includes(scope))
    fail(`${operationId} has invalid x-acornfox-parity ${JSON.stringify(scope)}`);
  return scope;
}

try {
  const config = await createConfig({ extends: ["minimal"] });
  const result = await bundle({ ref: schemaPath, config });
  const document = result.bundle.parsed;
  const operations = [];
  for (const [pathTemplate, pathItem] of Object.entries(document.paths ?? {})) {
    for (const method of ["get", "post", "put", "delete", "patch", "head", "options"]) {
      const operation = pathItem?.[method];
      if (!operation) continue;
      if (typeof operation.operationId !== "string" || operation.operationId.length === 0)
        fail(`${method.toUpperCase()} ${pathTemplate} has no operationId`);
      operations.push({
        operationId: operation.operationId,
        method: method.toUpperCase(),
        pathTemplate,
        successStatuses: successStatuses(operation, operation.operationId),
        proof: proofClass(document, pathItem, operation, method, operation.operationId),
        parity: parityScope(operation, operation.operationId),
        cli: parityScope(operation, operation.operationId) !== "integration_ui" && parityScope(operation, operation.operationId) !== "assistant_ui_only",
        webClient: parityScope(operation, operation.operationId) === "legacy_cli" ? "legacy" : parityScope(operation, operation.operationId) === "candidate_cli" ? "candidate" : parityScope(operation, operation.operationId) === "cli_only" ? "none" : parityScope(operation, operation.operationId) === "assistant_ui_only" ? "assistant" : "integration",
      });
    }
  }
  operations.sort((left, right) => left.operationId.localeCompare(right.operationId));
  if (new Set(operations.map((item) => item.operationId)).size !== operations.length)
    fail("operationIds must be unique");

  const sourceRequestType = document.components?.schemas?.CreateApplicationRequest?.properties?.source?.properties?.type?.enum;
  const sourceRevisionKind = document.components?.schemas?.SourceRevision?.properties?.kind?.enum;
  if (JSON.stringify(sourceRequestType) !== JSON.stringify(["public_git"]))
    fail("CreateApplicationRequest.source.type must remain exactly public_git");
  if (JSON.stringify(sourceRevisionKind) !== JSON.stringify(["git_https"]))
    fail("SourceRevision.kind must remain exactly git_https");

  writeFileSync(
    matrixPath,
    `${JSON.stringify({ sourceRequestType: sourceRequestType[0], sourceRevisionKind: sourceRevisionKind[0], operations })}\n`,
    { mode: 0o600 },
  );
  const environment = { ...process.env, ACORNFOX_PARITY_MATRIX: matrixPath };
  execFileSync("go", ["test", "./cmd/acornfox", "-run", "^TestAcornFoxOpenAPIParity$"], {
    cwd: repositoryRoot,
    env: environment,
    stdio: "inherit",
  });
  execFileSync(vitestPath, ["run", "src/acornfox/parity.test.ts"], {
    cwd: webRoot,
    env: environment,
    stdio: "inherit",
  });
  const cliOperations = operations.filter((operation) => operation.cli).length;
  const legacyWebOperations = operations.filter((operation) => operation.webClient === "legacy").length;
  const integrationWebOperations = operations.filter((operation) => operation.webClient === "integration").length;
  const assistantWebOperations = operations.filter((operation) => operation.webClient === "assistant").length;
  const candidateWebOperations = operations.filter((operation) => operation.webClient === "candidate").length;
  const cliOnlyOperations = operations.filter((operation) => operation.webClient === "none").length;
  console.log(`AcornFox parity passed: ${cliOperations} CLI, ${legacyWebOperations} legacy-Web, ${integrationWebOperations} integration-Web, ${assistantWebOperations} assistant-Web, ${candidateWebOperations} candidate-Web, ${cliOnlyOperations} CLI-only, and ${operations.length} declared operations.`);
} finally {
  rmSync(matrixDirectory, { recursive: true, force: true });
}
