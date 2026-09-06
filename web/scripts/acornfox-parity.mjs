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
    if (operationId !== "loginAcornFoxAdministrator")
      fail(`${operationId} is anonymous but is not the login operation`);
    return "anonymous-login";
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

function successStatus(operation, operationId) {
  const statuses = Object.keys(operation.responses ?? {}).filter((status) => /^2\d\d$/.test(status));
  if (statuses.length !== 1)
    fail(`${operationId} must declare exactly one 2xx response, found ${statuses.join(", ") || "none"}`);
  return Number(statuses[0]);
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
        successStatus: successStatus(operation, operation.operationId),
        proof: proofClass(document, pathItem, operation, method, operation.operationId),
        visible: true,
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
  console.log(`AcornFox parity passed: ${operations.length} visible operations in CLI and Web.`);
} finally {
  rmSync(matrixDirectory, { recursive: true, force: true });
}
