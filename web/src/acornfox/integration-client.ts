import { AcornFoxRequestError } from "./client";

const base = "/api/v1/acornfox";

type Fetcher = (
  input: RequestInfo | URL,
  init?: RequestInit,
) => Promise<Response>;

type JsonRecord = Record<string, unknown>;

export type HostMetrics = {
  schemaVersion: 1;
  availability: "available" | "warming_up" | "unavailable" | "unsupported";
  observedAt?: string;
  staleAfterSeconds: number;
  cpu?: { logicalCores: number; usagePercent?: number };
  memory?: { totalBytes: number; availableBytes: number; usedBytes: number };
  disk?: { mountpoint: "/"; totalBytes: number; freeBytes: number; usedBytes: number };
  network?: { interface: string; rxBytesPerSecond?: number; txBytesPerSecond?: number };
};

export type SetupState = "initialized" | "uninitialized" | "unavailable";

export type SourceMetadata = {
  sourceRevisionId: string;
  availability: "available" | "unavailable";
  repositoryUrl?: string;
};

export type DeploymentSource = {
  deploymentId: string;
  availability: "available" | "unavailable";
  sourceRevisionId?: string;
  commit?: string;
  ref?: string;
  repositoryUrl?: string;
};

export type SourceUpdate = { sourceRevisionId: string; status: "imported" };

export type AcornFoxOperationEvidence = {
  kind: "runtime_observation" | "response_observation";
  verdict: "observed" | "unhealthy";
  observedAt: string;
  httpStatus?: number;
};

export type AcornFoxOperationResult = {
  operationId: string;
  operationType: string;
  status: "accepted" | "running" | "verified" | "failed" | "unknown";
  taskId?: string;
  deploymentId?: string;
  acceptedAt: string;
  updatedAt: string;
  evidence?: AcornFoxOperationEvidence;
};

export interface AcornFoxIntegrationClient {
  setupState(): Promise<SetupState>;
  setup(input: { setupToken: string; password: string }): Promise<void>;
  hostMetrics(signal?: AbortSignal): Promise<HostMetrics>;
  sourceMetadata(applicationId: string, sourceRevisionId: string): Promise<SourceMetadata>;
  sourceUpdate(applicationId: string, input: { baseSourceRevisionId: string; ref: string }, idempotencyKey: string): Promise<SourceUpdate>;
  deploymentSource(applicationId: string, deploymentId: string): Promise<DeploymentSource>;
  operationResult(applicationId: string, operationId: string): Promise<AcornFoxOperationResult>;
}

function invalid(): never {
  throw new AcornFoxRequestError(undefined, "invalid_response", "服务返回的数据无法识别。");
}
function record(value: unknown): JsonRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? value as JsonRecord
    : invalid();
}
function string(value: unknown): string {
  return typeof value === "string" ? value : invalid();
}
function finite(value: unknown): number {
  return typeof value === "number" && Number.isFinite(value) ? value : invalid();
}
function integer(value: unknown): number {
  return Number.isInteger(value) ? finite(value) : invalid();
}
function optionalString(value: unknown): string | undefined {
  return value === undefined ? undefined : string(value);
}
function date(value: unknown): string {
  const result = string(value);
  return Number.isNaN(Date.parse(result)) ? invalid() : result;
}
function optionalDate(value: unknown): string | undefined {
  return value === undefined ? undefined : date(value);
}
function enumValue<T extends string>(value: unknown, choices: readonly T[]): T {
  return typeof value === "string" && choices.includes(value as T)
    ? value as T
    : invalid();
}
function exact(value: unknown, mandatory: readonly string[], allowed = mandatory): JsonRecord {
  const row = record(value);
  if (!mandatory.every((key) => Object.hasOwn(row, key))) return invalid();
  if (!Object.keys(row).every((key) => allowed.includes(key))) return invalid();
  return row;
}
function pathPart(value: string): string {
  return encodeURIComponent(value);
}
function csrfCookie(): string | undefined {
  if (typeof document === "undefined") return undefined;
  const entry = document.cookie.split(";").map((item) => item.trim())
    .find((item) => item.startsWith("__Host-acornfox_csrf="));
  if (!entry) return undefined;
  try {
    return decodeURIComponent(entry.slice("__Host-acornfox_csrf=".length));
  } catch {
    return undefined;
  }
}
function errorFromResponse(status: number, body: unknown): AcornFoxRequestError {
  const row = typeof body === "object" && body !== null ? body as JsonRecord : undefined;
  return new AcornFoxRequestError(
    status,
    typeof row?.code === "string" ? row.code : `http_${status}`,
    typeof row?.message === "string" ? row.message : "请求未完成，请稍后重试。",
  );
}
export function newIntegrationIdempotencyKey(): string {
  if (typeof crypto === "undefined" || typeof crypto.getRandomValues !== "function") invalid();
  if (typeof crypto.randomUUID === "function") return crypto.randomUUID();
  return Array.from(crypto.getRandomValues(new Uint8Array(16)), (byte) => byte.toString(16).padStart(2, "0")).join("");
}
function host(value: unknown): HostMetrics {
  const row = exact(value, ["schema_version", "availability", "stale_after_seconds"], [
    "schema_version", "availability", "observed_at", "stale_after_seconds", "cpu", "memory", "disk", "network",
  ]);
  if (integer(row.schema_version) !== 1 || integer(row.stale_after_seconds) < 0) invalid();
  const result: HostMetrics = {
    schemaVersion: 1,
    availability: enumValue(row.availability, ["available", "warming_up", "unavailable", "unsupported"]),
    staleAfterSeconds: integer(row.stale_after_seconds),
  };
  const observedAt = optionalDate(row.observed_at);
  if (observedAt) result.observedAt = observedAt;
  if (row.cpu !== undefined) {
    const cpu = exact(row.cpu, ["logical_cores"], ["logical_cores", "usage_percent"]);
    const usage = row.cpu === undefined ? undefined : cpu.usage_percent;
    result.cpu = { logicalCores: integer(cpu.logical_cores), ...(usage === undefined ? {} : { usagePercent: finite(usage) }) };
  }
  if (row.memory !== undefined) {
    const memory = exact(row.memory, ["total_bytes", "available_bytes", "used_bytes"]);
    result.memory = { totalBytes: integer(memory.total_bytes), availableBytes: integer(memory.available_bytes), usedBytes: integer(memory.used_bytes) };
  }
  if (row.disk !== undefined) {
    const disk = exact(row.disk, ["mountpoint", "total_bytes", "free_bytes", "used_bytes"]);
    if (disk.mountpoint !== "/") invalid();
    result.disk = { mountpoint: "/", totalBytes: integer(disk.total_bytes), freeBytes: integer(disk.free_bytes), usedBytes: integer(disk.used_bytes) };
  }
  if (row.network !== undefined) {
    const network = exact(row.network, ["interface"], ["interface", "rx_bytes_per_second", "tx_bytes_per_second"]);
    result.network = {
      interface: string(network.interface),
      ...(network.rx_bytes_per_second === undefined ? {} : { rxBytesPerSecond: finite(network.rx_bytes_per_second) }),
      ...(network.tx_bytes_per_second === undefined ? {} : { txBytesPerSecond: finite(network.tx_bytes_per_second) }),
    };
  }
  return result;
}
function sourceMetadata(value: unknown): SourceMetadata {
  const row = exact(value, ["source_revision_id", "availability"], ["source_revision_id", "availability", "repository_url"]);
  const repositoryUrl = optionalString(row.repository_url);
  return { sourceRevisionId: string(row.source_revision_id), availability: enumValue(row.availability, ["available", "unavailable"]), ...(repositoryUrl === undefined ? {} : { repositoryUrl }) };
}
function sourceUpdate(value: unknown): SourceUpdate {
  const row = exact(value, ["source_revision_id", "status"]);
  return { sourceRevisionId: string(row.source_revision_id), status: enumValue(row.status, ["imported"]) };
}
function deploymentSource(value: unknown): DeploymentSource {
  const row = exact(value, ["deployment_id", "availability"], ["deployment_id", "availability", "source_revision_id", "commit", "ref", "repository_url"]);
  const sourceRevisionId = optionalString(row.source_revision_id);
  const commit = optionalString(row.commit);
  const ref = optionalString(row.ref);
  const repositoryUrl = optionalString(row.repository_url);
  return {
    deploymentId: string(row.deployment_id), availability: enumValue(row.availability, ["available", "unavailable"]),
    ...(sourceRevisionId === undefined ? {} : { sourceRevisionId }), ...(commit === undefined ? {} : { commit }),
    ...(ref === undefined ? {} : { ref }), ...(repositoryUrl === undefined ? {} : { repositoryUrl }),
  };
}
function operation(value: unknown): AcornFoxOperationResult {
  const row = exact(value, ["operation_id", "operation_type", "status", "accepted_at", "updated_at"], [
    "operation_id", "operation_type", "status", "task_id", "deployment_id", "accepted_at", "updated_at", "evidence",
  ]);
  const status = enumValue(row.status, ["accepted", "running", "verified", "failed", "unknown"]);
  const taskId = optionalString(row.task_id);
  const deploymentId = optionalString(row.deployment_id);
  const acceptedAt = date(row.accepted_at);
  const updatedAt = date(row.updated_at);
  if (Date.parse(updatedAt) < Date.parse(acceptedAt)) invalid();
  let evidence: AcornFoxOperationEvidence | undefined;
  if (row.evidence !== undefined) {
    const fact = exact(row.evidence, ["kind", "verdict", "observed_at"], ["kind", "verdict", "observed_at", "http_status"]);
    const kind = enumValue(fact.kind, ["runtime_observation", "response_observation"]);
    const verdict = enumValue(fact.verdict, ["observed", "unhealthy"]);
    const httpStatus = fact.http_status === undefined ? undefined : integer(fact.http_status);
    if ((kind === "runtime_observation" && (verdict !== "observed" || httpStatus !== undefined)) || (httpStatus !== undefined && (httpStatus < 100 || httpStatus > 599))) invalid();
    evidence = { kind, verdict, observedAt: date(fact.observed_at), ...(httpStatus === undefined ? {} : { httpStatus }) };
  }
  if ((status === "verified") !== (evidence !== undefined)) invalid();
  return { operationId: string(row.operation_id), operationType: string(row.operation_type), status, ...(taskId === undefined ? {} : { taskId }), ...(deploymentId === undefined ? {} : { deploymentId }), acceptedAt, updatedAt, ...(evidence === undefined ? {} : { evidence }) };
}

export function createAcornFoxIntegrationClient(fetcher: Fetcher = fetch): AcornFoxIntegrationClient {
  async function request<T>(path: string, parse: (value: unknown) => T, init: RequestInit = {}, expected = 200): Promise<T> {
    const headers = new Headers(init.headers);
    if (init.body !== undefined) headers.set("Content-Type", "application/json");
    if (init.method && init.method !== "GET") {
      const token = csrfCookie();
      if (token) headers.set("X-AcornFox-CSRF", token);
    }
    let response: Response;
    try {
      response = await fetcher(`${base}${path}`, { ...init, headers, credentials: "include", redirect: "error" });
    } catch {
      throw new AcornFoxRequestError(undefined, "network_error", "请求未完成，请检查连接后重试。");
    }
    if (!response.ok || response.status !== expected) {
      let body: unknown;
      try { body = await response.json(); } catch { /* no structured error body */ }
      throw errorFromResponse(response.status, body);
    }
    if (expected === 204) return parse(undefined);
    try { return parse(await response.json()); } catch (error) {
      if (error instanceof AcornFoxRequestError) throw error;
      return invalid();
    }
  }
  return {
    setupState: () => request("/setup", (value) => enumValue(exact(value, ["state"]).state, ["initialized", "uninitialized", "unavailable"])),
    setup: ({ setupToken, password }) => {
      if (!setupToken || !password) throw new AcornFoxRequestError(422, "invalid_input", "初始化令牌和管理员密码不能为空。");
      return request("/setup", (value) => {
        const row = exact(value, ["initialized"]);
        return row.initialized === true ? undefined : invalid();
      }, { method: "POST", body: JSON.stringify({ setup_token: setupToken, password }) }, 201);
    },
    hostMetrics: (signal) => request("/host/metrics", host, { signal }),
    sourceMetadata: (applicationId, sourceRevisionId) => request(`/apps/${pathPart(applicationId)}/sources/${pathPart(sourceRevisionId)}/metadata`, sourceMetadata),
    sourceUpdate: (applicationId, input, idempotencyKey) => {
      if (!input.baseSourceRevisionId || !input.ref.trim() || !idempotencyKey) throw new AcornFoxRequestError(422, "invalid_input", "来源版本、引用和请求标识不能为空。");
      return request(`/apps/${pathPart(applicationId)}/sources`, sourceUpdate, { method: "POST", headers: { "Idempotency-Key": idempotencyKey }, body: JSON.stringify({ base_source_revision_id: input.baseSourceRevisionId, ref: input.ref.trim() }) }, 201);
    },
    deploymentSource: (applicationId, deploymentId) => request(`/apps/${pathPart(applicationId)}/deliveries/${pathPart(deploymentId)}/source`, deploymentSource),
    operationResult: (applicationId, operationId) => request(`/apps/${pathPart(applicationId)}/operations/${pathPart(operationId)}`, operation),
  };
}
