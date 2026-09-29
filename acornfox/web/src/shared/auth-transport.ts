import { resolveCsrfToken } from "../acornfox/csrf";
import type { components } from "../api/acornfox-generated-schema";

export type SetupState = "initialized" | "uninitialized" | "unavailable";

export type Session = {
  authenticated: boolean;
  idle_expires_at: string;
  absolute_expires_at: string;
};

export type CoreStatus = {
  storage: string;
  package_management: string;
  capabilities: string[];
};

export type HostMetricsAvailability = components["schemas"]["HostMetricsResponse"]["availability"];
export type HostMetricsResponse = components["schemas"]["HostMetricsResponse"];
export type HostMetricsRecentResponse = components["schemas"]["HostMetricsRecentResponse"];

export type ImagePlanInput = { app_name: string; image: string; port?: number; environment?: Record<string, string> };
export type ImagePlan = {
  id: string; app_name: string; status: "planned" | "needs_input"; plan_digest: string;
  canonical_input: { app_name: string; repository: string; resolved_ref: string; port?: number;
    environment?: { name: string; value: string; kind?: string }[];
    resources: { cpu_millis: number; memory_bytes: number; disk_reservation_bytes?: number; pids?: number };
    volumes?: { name: string; mount_path: string; size_bytes: number; read_only?: boolean }[] };
  resolved_image: { repository: string; digest: string; architecture: string; os: string; resolved_tag?: string };
  missing_inputs: string[];
};
export type ImageConfirmation = { operation_id: string; plan_id: string; plan_digest: string; status: string };
export type ImageOperation = { operation_id: string; application_id: string; environment_id: string; plan_id: string; plan_digest: string;
  state: "pending" | "running" | "unknown" | "succeeded" | "failed" | "cancelled";
  reason?: string; action_required?: boolean;
  result?: { deployment_id: string; release_id: string; status: string; container_id?: string;
    image_id?: string; host_ip?: string; host_port?: number; container_port?: number; endpoint?: string } };

export type ImageLifecycleAction = "stop" | "start" | "restart";
export type ImageLifecycleOperation = {
  operation_id: string; task_id: string; deployment_id: string; release_id: string;
  application_id: string; environment_id: string; deploy_operation_id: string; plan_id: string;
  plan_digest: string; manifest_digest: string; container_id: string; image_id: string;
  host_port: number; container_port: number; action: ImageLifecycleAction;
  state: ImageOperation["state"]; created_at: string; recovery_required: boolean; reason?: string;
  result?: { running: boolean; verified_identity: boolean; container_id: string; image_id: string;
    manifest_digest: string; host_port: number; container_port: number; endpoint_ready: boolean; observed_at: string };
};

export type ManagedImageCommandSummary = { operation_id: string; action: ImageLifecycleAction; state: ImageOperation["state"] };
export type ManagedImageApplicationSummary = {
  application_id: string; name: string; environment_id: string; plan_id: string; plan_digest: string;
  deploy_operation_id: string; deploy_state: ImageOperation["state"]; deployment_id?: string; deployment_state?: string;
  updated_at: string; active_command?: ManagedImageCommandSummary; last_command?: ManagedImageCommandSummary;
};
export type ManagedImageApplicationList = { items: ManagedImageApplicationSummary[]; truncated: boolean };

export type ManagedImageObservation = {
  state: NonNullable<ImageLifecycleOperation["result"]>;
  records?: { stream: "stdout" | "stderr"; data: string }[];
  source_limited: boolean;
};

export type ImageMetricLimits = { cpu_millis: number; memory_bytes: number; pids: number };
export type ImageMetricNumbers = {
  cpu_percent?: number; cpu_usage_millis?: number; memory_usage_bytes?: number; memory_limit_bytes?: number;
  network_rx_bytes?: number; network_tx_bytes?: number; pids_current?: number; limits?: ImageMetricLimits;
};
export type ManagedImageMetrics = ImageMetricNumbers & {
  state: NonNullable<ImageLifecycleOperation["result"]>; available: boolean;
  unavailable_reason?: "not_running" | "read_unavailable" | "runtime_changed";
  sampled_at?: string; process_started_at?: string;
};
export type ManagedImageMetricPoint = ImageMetricNumbers & {
  segment_id: number; container_id: string; process_started_at?: string; observed_at: string;
  available: boolean; unavailable_reason?: string;
};
export type ManagedImageMetricsRecent = {
  deployment_id: string; container_id: string; history_epoch: string; history_start?: string;
  segment_start?: string; current_segment_id: number; scheduled: boolean; selection_limited: boolean;
  stale_after_seconds: number; stale: boolean;
  recording_status: "not_selected" | "warming_up" | "recording" | "stale";
  reason?: "outside_sampling_selection" | "first_sample_pending" | "sample_expired" | "read_failed" | "not_running" | "read_unavailable" | "runtime_changed";
  samples: ManagedImageMetricPoint[];
};

export type ImageDomainAction = "ensure" | "remove";
export type ImageDomainOperation = {
  operation_id: string; task_id: string; approval_id: string; deployment_id: string;
  hostname: string; action: ImageDomainAction; state: "pending" | "running" | "unknown" | "succeeded" | "failed";
  created_at: string; reason?: string;
  result?: { observed_at: string; certificate_fingerprint?: string; certificate_expires_at?: string };
};
export type ImageDomainCurrent = {
  operation: ImageDomainOperation; desired_public: boolean;
  local_route_state: "desired" | "configured" | "reconcile_required" | "disabled";
  deployment_status: "running" | "stopped" | "deploying" | "failed";
  availability: "pending" | "degraded" | "unverified" | "disabled";
};

export type Fetcher = (
  input: RequestInfo | URL,
  init?: RequestInit,
) => Promise<Response>;

export class AcornFoxRequestError extends Error {
  constructor(
    public readonly status: number | undefined,
    public readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = "AcornFoxRequestError";
  }
  get kind(): "authentication" | "unavailable" | "conflict" | "failed" {
    if (this.status === 401 || this.status === 429) return "authentication";
    if (this.status === 503 || this.status === undefined) return "unavailable";
    if (this.status === 409) return "conflict";
    return "failed";
  }
}

export interface CoreAuthClient {
  imageApps(limit?: number, signal?: AbortSignal): Promise<ManagedImageApplicationList>;
  createImagePlan(input: ImagePlanInput, signal?: AbortSignal): Promise<ImagePlan>;
  imagePlan(id: string, signal?: AbortSignal): Promise<ImagePlan>;
  confirmImagePlan(input: { plan_id: string; plan_digest: string; idempotency_key: string }, signal?: AbortSignal): Promise<ImageConfirmation>;
  imageOperation(id: string, signal?: AbortSignal): Promise<ImageOperation>;
  createImageLifecycle(deploymentId: string, input: { action: ImageLifecycleAction; idempotency_key: string }, signal?: AbortSignal): Promise<ImageLifecycleOperation>;
  imageLifecycleOperation(id: string, signal?: AbortSignal): Promise<ImageLifecycleOperation>;
  imageObservation(deploymentId: string, signal?: AbortSignal): Promise<ManagedImageObservation>;
  imageLogs(deploymentId: string, options?: { tail?: number; since?: string }, signal?: AbortSignal): Promise<ManagedImageObservation>;
  imageMetrics(deploymentId: string, signal?: AbortSignal): Promise<ManagedImageMetrics>;
  imageMetricsRecent(deploymentId: string, limit?: number, signal?: AbortSignal): Promise<ManagedImageMetricsRecent>;
  createImageDomainCommand(deploymentId: string, input: { hostname: string; action: ImageDomainAction; idempotency_key: string }, signal?: AbortSignal): Promise<ImageDomainOperation>;
  imageDomainCurrent(deploymentId: string, signal?: AbortSignal): Promise<ImageDomainCurrent | null>;
  imageDomainOperation(operationId: string, signal?: AbortSignal): Promise<ImageDomainOperation>;
  setupState(): Promise<SetupState>;
  setup(input: { setupToken: string; password: string }): Promise<void>;
  login(password: string): Promise<Session>;
  logout(): Promise<void>;
  session(): Promise<Session>;
  changePassword(currentPassword: string, newPassword: string): Promise<void>;
  coreStatus(): Promise<CoreStatus>;
  hostMetrics(signal?: AbortSignal): Promise<HostMetricsResponse>;
  hostMetricsRecent(limit?: number, signal?: AbortSignal): Promise<HostMetricsRecentResponse>;
}

const base = "/api/v1/acornfox";

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function invalid(message = "服务返回的数据无法识别。"): never {
  throw new AcornFoxRequestError(undefined, "invalid_response", message);
}

function record(value: unknown): Record<string, unknown> {
  return isRecord(value) ? value : invalid();
}

function text(value: unknown): string {
  return typeof value === "string" ? value : invalid();
}

function flag(value: unknown): boolean {
  return typeof value === "boolean" ? value : invalid();
}

function isOneOf<T extends string>(value: unknown, choices: readonly T[]): value is T {
  return typeof value === "string" && choices.some((choice) => choice === value);
}

function enumValue<T extends string>(value: unknown, choices: readonly T[]): T {
  return isOneOf(value, choices) ? value : invalid();
}

function dateTime(value: unknown): string {
  const result = text(value);
  return /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/.test(
    result,
  ) && !Number.isNaN(Date.parse(result))
    ? result
    : invalid();
}

function strictDateTime(value: unknown): string {
  const result = text(value);
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/.exec(result);
  if (!match) invalid();
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const hour = Number(match[4]);
  const min = Number(match[5]);
  const sec = Number(match[6]);
  if (month < 1 || month > 12 || day < 1 || hour > 23 || min > 59 || sec > 60) invalid();

  const maxDays = new Date(Date.UTC(year, month, 0)).getUTCDate();
  if (day > maxDays) invalid();

  const parsed = new Date(result);
  if (Number.isNaN(parsed.getTime())) invalid();

  return result;
}

function exact(
  value: unknown,
  mandatory: readonly string[],
  allowed: readonly string[] = mandatory,
): Record<string, unknown> {
  const row = record(value);
  if (!mandatory.every((key) => Object.hasOwn(row, key))) return invalid();
  if (!Object.keys(row).every((key) => allowed.includes(key))) return invalid();
  return row;
}

function sessionDecoder(value: unknown): Session {
  const row = exact(value, [
    "authenticated",
    "idle_expires_at",
    "absolute_expires_at",
  ]);
  return {
    authenticated: flag(row.authenticated),
    idle_expires_at: dateTime(row.idle_expires_at),
    absolute_expires_at: dateTime(row.absolute_expires_at),
  };
}

function coreStatusDecoder(value: unknown): CoreStatus {
  const row = exact(
    value,
    ["storage", "package_management", "capabilities"],
    ["storage", "package_management", "capabilities"],
  );
  if (!Array.isArray(row.capabilities)) invalid();
  return {
    storage: text(row.storage),
    package_management: text(row.package_management),
    capabilities: row.capabilities.map(text),
  };
}

function isIntegerNonNegative(v: unknown): v is number {
  return typeof v === "number" && Number.isInteger(v) && v >= 0;
}

function isIntegerPositive(v: unknown): v is number {
  return typeof v === "number" && Number.isInteger(v) && v >= 1;
}

function isFiniteNonNegative(v: unknown): v is number {
  return typeof v === "number" && Number.isFinite(v) && v >= 0;
}

export function hostMetricsDecoder(value: unknown): HostMetricsResponse {
  const allowedKeys = [
    "schema_version",
    "availability",
    "stale_after_seconds",
    "observed_at",
    "cpu",
    "memory",
    "disk",
    "network",
  ];
  const row = exact(value, ["schema_version", "availability", "stale_after_seconds"], allowedKeys);

  if (row.schema_version !== 1) invalid();
  const availability = enumValue(row.availability, [
    "available",
    "warming_up",
    "unavailable",
    "unsupported",
  ]);
  if (!isIntegerPositive(row.stale_after_seconds)) invalid();
  const stale_after_seconds = row.stale_after_seconds as number;

  let observed_at: string | undefined;
  if (row.observed_at !== undefined) {
    if (row.observed_at === null) invalid();
    observed_at = strictDateTime(row.observed_at);
  }

  // Unavailable and Unsupported must NOT carry metric objects
  if (availability === "unavailable" || availability === "unsupported") {
    if (
      row.cpu !== undefined ||
      row.memory !== undefined ||
      row.disk !== undefined ||
      row.network !== undefined
    ) {
      invalid();
    }
    return {
      schema_version: 1,
      availability,
      observed_at,
      stale_after_seconds,
    };
  }

  // Warming up: allows either initial unpopulated shape OR sampled shape with missing delta
  if (availability === "warming_up") {
    const allAbsent =
      row.observed_at === undefined &&
      row.cpu === undefined &&
      row.memory === undefined &&
      row.disk === undefined &&
      row.network === undefined;
    if (allAbsent) {
      return {
        schema_version: 1,
        availability,
        stale_after_seconds,
      };
    }
    if (observed_at === undefined || row.cpu === undefined || row.memory === undefined || row.disk === undefined) {
      invalid();
    }
  }

  // Available strictly requires observed_at, cpu, memory, disk
  if (availability === "available") {
    if (observed_at === undefined || row.cpu === undefined || row.memory === undefined || row.disk === undefined) {
      invalid();
    }
  }

  let cpu: HostMetricsResponse["cpu"];
  if (row.cpu !== undefined) {
    if (row.cpu === null) invalid();
    const c = exact(row.cpu, ["logical_cores"], ["logical_cores", "usage_percent"]);
    if (!isIntegerPositive(c.logical_cores)) invalid();
    let usage_percent: number | undefined;
    if (c.usage_percent !== undefined) {
      if (c.usage_percent === null || !isFiniteNonNegative(c.usage_percent) || (c.usage_percent as number) > 100) invalid();
      usage_percent = c.usage_percent as number;
    }
    if (availability === "available" && usage_percent === undefined) {
      invalid();
    }
    cpu = { logical_cores: c.logical_cores as number, usage_percent };
  }

  let memory: HostMetricsResponse["memory"];
  if (row.memory !== undefined) {
    if (row.memory === null) invalid();
    const m = exact(row.memory, ["total_bytes", "available_bytes", "used_bytes"]);
    if (
      !isIntegerNonNegative(m.total_bytes) ||
      !isIntegerNonNegative(m.available_bytes) ||
      !isIntegerNonNegative(m.used_bytes)
    ) {
      invalid();
    }
    const tot = m.total_bytes as number;
    const avail = m.available_bytes as number;
    const used = m.used_bytes as number;
    if (avail > tot || used > tot) invalid();
    if (availability === "available" && tot === 0) invalid();
    memory = { total_bytes: tot, available_bytes: avail, used_bytes: used };
  }

  let disk: HostMetricsResponse["disk"];
  if (row.disk !== undefined) {
    if (row.disk === null) invalid();
    const d = exact(row.disk, ["mountpoint", "total_bytes", "free_bytes", "used_bytes"]);
    if (d.mountpoint !== "/") invalid();
    if (
      !isIntegerNonNegative(d.total_bytes) ||
      !isIntegerNonNegative(d.free_bytes) ||
      !isIntegerNonNegative(d.used_bytes)
    ) {
      invalid();
    }
    const tot = d.total_bytes as number;
    const free = d.free_bytes as number;
    const used = d.used_bytes as number;
    if (free > tot || used > tot) invalid();
    if (availability === "available" && tot === 0) invalid();
    disk = { mountpoint: "/", total_bytes: tot, free_bytes: free, used_bytes: used };
  }

  let network: HostMetricsResponse["network"];
  if (row.network !== undefined) {
    if (row.network === null) invalid();
    const n = exact(row.network, ["interface"], ["interface", "rx_bytes_per_second", "tx_bytes_per_second"]);
    const iface = text(n.interface);
    if (!iface || iface.length > 15) invalid();
    let rx: number | undefined;
    if (n.rx_bytes_per_second !== undefined) {
      if (n.rx_bytes_per_second === null || !isFiniteNonNegative(n.rx_bytes_per_second)) invalid();
      rx = n.rx_bytes_per_second as number;
    }
    let tx: number | undefined;
    if (n.tx_bytes_per_second !== undefined) {
      if (n.tx_bytes_per_second === null || !isFiniteNonNegative(n.tx_bytes_per_second)) invalid();
      tx = n.tx_bytes_per_second as number;
    }
    network = { interface: iface, rx_bytes_per_second: rx, tx_bytes_per_second: tx };
  }

  return {
    schema_version: 1,
    availability,
    observed_at,
    stale_after_seconds,
    cpu,
    memory,
    disk,
    network,
  };
}

export function hostMetricsRecentDecoder(
  value: unknown,
  requestLimit = 60,
): HostMetricsRecentResponse {
  const row = exact(value, [
    "schema_version",
    "availability",
    "generated_at",
    "capacity",
    "retention_seconds",
    "points",
  ]);

  if (row.schema_version !== 1) invalid();
  const availability = enumValue(row.availability, [
    "available",
    "warming_up",
    "unavailable",
    "unsupported",
  ]);
  const generated_at = strictDateTime(row.generated_at);
  if (row.capacity !== 360 || row.retention_seconds !== 1800) invalid();
  if (!Array.isArray(row.points)) invalid();

  const maxPoints = Math.min(requestLimit, 360);
  if (row.points.length > maxPoints) invalid();

  const genMs = new Date(generated_at).getTime();
  const minValidMs = genMs - 1800 * 1000 - 5000;

  let lastPointMs = -Infinity;
  const points: HostMetricsResponse[] = [];

  for (const rawPoint of row.points) {
    const pt = hostMetricsDecoder(rawPoint);
    if (!pt.observed_at) invalid();
    const ptMs = new Date(pt.observed_at).getTime();
    if (Number.isNaN(ptMs)) invalid();
    if (ptMs > genMs + 2000) invalid();
    if (ptMs < minValidMs) invalid();
    if (ptMs < lastPointMs) invalid();

    lastPointMs = ptMs;
    points.push(pt);
  }

  return {
    schema_version: 1,
    availability,
    generated_at,
    capacity: 360,
    retention_seconds: 1800,
    points,
  };
}

function identifier(value: unknown): string { const v = text(value); return v.length > 0 ? v : invalid(); }
function digest(value: unknown): string { const v = text(value); return /^sha256:[a-f0-9]{64}$/.test(v) ? v : invalid(); }
function numberValue(value: unknown): number { return isIntegerNonNegative(value) ? value : invalid(); }
function portValue(value: unknown): number { const v = numberValue(value); return v > 0 && v <= 65535 ? v : invalid(); }

export function managedImageApplicationsDecoder(value: unknown): ManagedImageApplicationList {
  const row = exact(value, ["items", "truncated"]);
  if (!Array.isArray(row.items) || row.items.length > 100) return invalid();
  const command = (value: unknown): ManagedImageCommandSummary => {
    const c = exact(value, ["operation_id", "action", "state"]);
    return { operation_id: identifier(c.operation_id), action: enumValue(c.action, ["stop", "start", "restart"]), state: enumValue(c.state, ["pending", "running", "unknown", "succeeded", "failed", "cancelled"]) };
  };
  const ids = new Set<string>();
  const items = row.items.map((value): ManagedImageApplicationSummary => {
    const r = exact(value, ["application_id", "name", "environment_id", "plan_id", "plan_digest", "deploy_operation_id", "deploy_state", "updated_at"], ["application_id", "name", "environment_id", "plan_id", "plan_digest", "deploy_operation_id", "deploy_state", "updated_at", "deployment_id", "deployment_state", "active_command", "last_command"]);
    const id = identifier(r.application_id);
    if (ids.has(id)) invalid(); ids.add(id);
    const active = r.active_command === undefined ? undefined : command(r.active_command);
    if (active && !["pending", "running", "unknown"].includes(active.state)) invalid();
    if ((active || r.last_command !== undefined) && r.deployment_id === undefined) invalid();
    if (active?.operation_id === r.deploy_operation_id) invalid();

    return { application_id: id, name: text(r.name), environment_id: identifier(r.environment_id), plan_id: identifier(r.plan_id), plan_digest: digest(r.plan_digest), deploy_operation_id: identifier(r.deploy_operation_id), deploy_state: enumValue(r.deploy_state, ["pending", "running", "unknown", "succeeded", "failed", "cancelled"]), updated_at: dateTime(r.updated_at), deployment_id: r.deployment_id === undefined ? undefined : identifier(r.deployment_id), deployment_state: r.deployment_state === undefined ? undefined : enumValue(r.deployment_state, ["deploying", "running", "failed", "stopped"]), active_command: active, last_command: r.last_command === undefined ? undefined : command(r.last_command) };
  });
  return { items, truncated: flag(row.truncated) };
}

export function imagePlanDecoder(value: unknown): ImagePlan {
  const row = exact(value, ["id", "admin_id", "app_name", "status", "plan_digest", "canonical_input", "resolved_image", "resolver_provenance", "created_at", "updated_at"],
    ["id", "admin_id", "app_name", "status", "plan_digest", "canonical_input", "resolved_image", "resolver_provenance", "missing_inputs", "created_at", "updated_at"]);
  identifier(row.admin_id); dateTime(row.created_at); dateTime(row.updated_at);
  const c = exact(row.canonical_input, ["app_name", "repository", "resolved_ref", "resources"], ["app_name", "repository", "resolved_ref", "resources", "port", "environment", "volumes"]);
  const r = exact(c.resources, ["cpu_millis", "memory_bytes"], ["cpu_millis", "memory_bytes", "disk_reservation_bytes", "pids"]);
  const image = exact(row.resolved_image, ["repository", "digest", "architecture", "os"], ["repository", "digest", "architecture", "os", "resolved_tag"]);
  const provenance = exact(row.resolver_provenance, ["provider", "evidence_ref", "digest", "resolved_at"]);
  identifier(provenance.provider); text(provenance.evidence_ref); dateTime(provenance.resolved_at);
  const imageDigest = digest(image.digest);
  if (provenance.digest !== imageDigest || image.os !== "linux" || image.architecture !== "amd64" || c.repository !== image.repository || c.app_name !== row.app_name) invalid();
  const status = enumValue(row.status, ["planned", "needs_input"]);
  const missing = row.missing_inputs === undefined ? [] : row.missing_inputs;
  if (!Array.isArray(missing)) invalid();
  const missing_inputs = missing.map(text);
  if (status === "planned" && missing_inputs.length !== 0) invalid();
  if (status === "needs_input" && (missing_inputs.length !== 1 || missing_inputs[0] !== "container_port")) invalid();
  const port = c.port === undefined ? undefined : portValue(c.port);
  if (status === "planned" && port === undefined) invalid();
  if (status === "needs_input" && port !== undefined) invalid();
  const environment = c.environment === undefined ? undefined : (() => {
    if (!Array.isArray(c.environment)) return invalid();
    return c.environment.map((v) => { const e = exact(v, ["name", "value"], ["name", "value", "kind"]); return { name: identifier(e.name), value: text(e.value), kind: e.kind === undefined ? undefined : text(e.kind) }; });
  })();
  const volumes = c.volumes === undefined ? undefined : (() => {
    if (!Array.isArray(c.volumes)) return invalid();
    return c.volumes.map((v) => { const e = exact(v, ["name", "mount_path", "size_bytes"], ["name", "mount_path", "size_bytes", "read_only"]); return { name: identifier(e.name), mount_path: text(e.mount_path), size_bytes: numberValue(e.size_bytes), read_only: e.read_only === undefined ? undefined : flag(e.read_only) }; });
  })();
  return { id: identifier(row.id), app_name: identifier(row.app_name), status, plan_digest: digest(row.plan_digest), missing_inputs,
    canonical_input: { app_name: identifier(c.app_name), repository: identifier(c.repository), resolved_ref: identifier(c.resolved_ref), port, environment, volumes,
      resources: { cpu_millis: numberValue(r.cpu_millis), memory_bytes: numberValue(r.memory_bytes), disk_reservation_bytes: r.disk_reservation_bytes === undefined ? undefined : numberValue(r.disk_reservation_bytes), pids: r.pids === undefined ? undefined : numberValue(r.pids) } },
    resolved_image: { repository: identifier(image.repository), digest: imageDigest, architecture: text(image.architecture), os: text(image.os), resolved_tag: image.resolved_tag === undefined ? undefined : text(image.resolved_tag) } };
}
export function imageConfirmationDecoder(value: unknown): ImageConfirmation {
  const r = exact(value, ["application_id", "environment_id", "operation_id", "task_id", "plan_id", "plan_digest", "status", "created_at"]);
  identifier(r.application_id); identifier(r.environment_id); identifier(r.task_id); dateTime(r.created_at);
  return { operation_id: identifier(r.operation_id), plan_id: identifier(r.plan_id), plan_digest: digest(r.plan_digest), status: text(r.status) };
}
export function imageOperationDecoder(value: unknown): ImageOperation {
  const r = exact(value, ["operation_id", "application_id", "environment_id", "operation_type", "state", "plan_id", "plan_digest", "task_id", "created_at", "updated_at"],
    ["operation_id", "application_id", "environment_id", "operation_type", "state", "plan_id", "plan_digest", "task_id", "created_at", "updated_at", "result", "reason", "action_required"]);
  identifier(r.application_id); identifier(r.environment_id); text(r.operation_type); text(r.task_id); dateTime(r.created_at); dateTime(r.updated_at);
  let result: ImageOperation["result"];
  if (r.result !== undefined) {
    const v = exact(r.result, ["deployment_id", "release_id", "status"], ["deployment_id", "release_id", "status", "container_id", "image_id", "host_ip", "host_port", "container_port", "endpoint"]);
    result = { deployment_id: identifier(v.deployment_id), release_id: identifier(v.release_id), status: text(v.status),
      container_id: v.container_id === undefined ? undefined : text(v.container_id), image_id: v.image_id === undefined ? undefined : text(v.image_id),
      host_ip: v.host_ip === undefined ? undefined : text(v.host_ip), host_port: v.host_port === undefined ? undefined : portValue(v.host_port),
      container_port: v.container_port === undefined ? undefined : portValue(v.container_port), endpoint: v.endpoint === undefined ? undefined : text(v.endpoint) };
    if (result.endpoint !== undefined && (result.status !== "running" || result.host_ip !== "127.0.0.1" || result.endpoint !== `http://127.0.0.1:${result.host_port}` || result.container_port === undefined)) invalid();
  }
  return { operation_id: identifier(r.operation_id), application_id: identifier(r.application_id), environment_id: identifier(r.environment_id), plan_id: identifier(r.plan_id), plan_digest: digest(r.plan_digest), state: enumValue(r.state, ["pending", "running", "unknown", "succeeded", "failed", "cancelled"]), reason: r.reason === undefined ? undefined : text(r.reason), action_required: r.action_required === undefined ? undefined : flag(r.action_required), result };
}

export function imageLifecycleOperationDecoder(value: unknown): ImageLifecycleOperation {
  const required = ["operation_id", "task_id", "deployment_id", "release_id", "application_id", "environment_id", "deploy_operation_id", "plan_id", "plan_digest", "manifest_digest", "container_id", "image_id", "host_port", "container_port", "action", "state", "created_at", "recovery_required"];
  const row = exact(value, required, [...required, "result", "reason"]);
  const operation: ImageLifecycleOperation = {
    operation_id: identifier(row.operation_id), task_id: identifier(row.task_id), deployment_id: identifier(row.deployment_id), release_id: identifier(row.release_id),
    application_id: identifier(row.application_id), environment_id: identifier(row.environment_id), deploy_operation_id: identifier(row.deploy_operation_id), plan_id: identifier(row.plan_id),
    plan_digest: digest(row.plan_digest), manifest_digest: digest(row.manifest_digest), container_id: identifier(row.container_id), image_id: digest(row.image_id),
    host_port: portValue(row.host_port), container_port: portValue(row.container_port), action: enumValue(row.action, ["stop", "start", "restart"]),
    state: enumValue(row.state, ["pending", "running", "unknown", "succeeded", "failed", "cancelled"]), created_at: dateTime(row.created_at), recovery_required: flag(row.recovery_required),
  };
  if (operation.operation_id === operation.deploy_operation_id || operation.recovery_required !== (operation.state === "unknown")) invalid();
  if (Object.hasOwn(row, "reason")) {
    if (operation.state !== "failed" && operation.state !== "unknown") invalid();
    const reason = text(row.reason);
    if (new TextEncoder().encode(reason).length > 1024 || /\p{Cc}/u.test(reason)) invalid();
    operation.reason = reason;
  }
  if (row.result !== undefined) {
    const r = exact(row.result, ["running", "verified_identity", "container_id", "image_id", "manifest_digest", "host_port", "container_port", "endpoint_ready", "observed_at"]);
    const result = { running: flag(r.running), verified_identity: flag(r.verified_identity), container_id: identifier(r.container_id), image_id: digest(r.image_id), manifest_digest: digest(r.manifest_digest),
      host_port: numberValue(r.host_port), container_port: numberValue(r.container_port), endpoint_ready: flag(r.endpoint_ready), observed_at: dateTime(r.observed_at) };
    if (operation.state !== "succeeded" || !result.verified_identity || result.container_id !== operation.container_id || result.image_id !== operation.image_id || result.manifest_digest !== operation.manifest_digest || result.host_port > 65535 || result.container_port > 65535 || Date.parse(result.observed_at) < Date.parse(operation.created_at)) invalid();
    if (operation.action === "stop") {
      if (result.running || result.endpoint_ready || (result.host_port !== 0 && result.host_port !== operation.host_port) || (result.container_port !== 0 && result.container_port !== operation.container_port)) invalid();
    } else if (!result.running || !result.endpoint_ready || result.host_port !== operation.host_port || result.container_port !== operation.container_port) invalid();
    operation.result = result;
  } else if (operation.state === "succeeded") invalid();
  return operation;
}

export function managedImageObservationDecoder(value: unknown, now = Date.now()): ManagedImageObservation {
  const row = exact(value, ["state", "source_limited"], ["state", "records", "source_limited"]);
  const v = exact(row.state, ["running", "verified_identity", "container_id", "image_id", "manifest_digest", "host_port", "container_port", "endpoint_ready", "observed_at"]);
  const state = { running: flag(v.running), verified_identity: flag(v.verified_identity), container_id: identifier(v.container_id), image_id: digest(v.image_id), manifest_digest: digest(v.manifest_digest), host_port: portValue(v.host_port), container_port: portValue(v.container_port), endpoint_ready: flag(v.endpoint_ready), observed_at: dateTime(v.observed_at) };
  // Core/role enforce their host-clock ten-second freshness. Permit a small
  // browser clock skew; subsequent UI expiry uses local elapsed receipt time.
  const age = now - Date.parse(state.observed_at);
  if (!state.verified_identity || state.endpoint_ready || age < -30000 || age > 40000) invalid();
  const source_limited = flag(row.source_limited);
  let records: ManagedImageObservation["records"];
  if (row.records !== undefined) {
    if (!Array.isArray(row.records) || row.records.length > 64) invalid();
    let bytes = 0;
    records = row.records.map((entry) => {
      const line = exact(entry, ["stream", "data"]);
      const data = text(line.data); if (!data) invalid();
      bytes += new TextEncoder().encode(data).length;
      return { stream: enumValue(line.stream, ["stdout", "stderr"]), data };
    });
    if (bytes > 8192) invalid();
  }
  return { state, records, source_limited };
}

const metricFields = ["cpu_percent", "cpu_usage_millis", "memory_usage_bytes", "memory_limit_bytes", "network_rx_bytes", "network_tx_bytes", "pids_current", "limits"];
function metricNumber(value: unknown, integer = false): number {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0 || (integer && !Number.isSafeInteger(value))) invalid();
  return value;
}
function metricNumbers(row: Record<string, unknown>): ImageMetricNumbers {
  const result: ImageMetricNumbers = {};
  for (const key of metricFields.slice(0, -1) as (keyof Omit<ImageMetricNumbers, "limits">)[]) {
    if (Object.hasOwn(row, key)) result[key] = metricNumber(row[key], key !== "cpu_percent");
  }
  if (Object.hasOwn(row, "limits")) {
    const limits = exact(row.limits, ["cpu_millis", "memory_bytes", "pids"]);
    result.limits = { cpu_millis: metricNumber(limits.cpu_millis, true), memory_bytes: metricNumber(limits.memory_bytes, true), pids: metricNumber(limits.pids, true) };
  }
  if ((result.network_rx_bytes === undefined) !== (result.network_tx_bytes === undefined) || (result.cpu_percent !== undefined && result.cpu_usage_millis === undefined)) invalid();
  return result;
}
// Go's time.Time with omitempty may encode its zero value as year 0001.
function metricTime(value: unknown): string | undefined {
  if (value === undefined) return undefined;
  const parsed = dateTime(value);
  return parsed === "0001-01-01T00:00:00Z" ? undefined : parsed;
}
function metricAvailability(numbers: ImageMetricNumbers, available: boolean, reason: unknown, sampledAt: unknown, startedAt: unknown) {
  const sampled = metricTime(sampledAt), started = metricTime(startedAt);
  if (available) {
    if (reason !== undefined || sampled === undefined || started === undefined ||
        (numbers.cpu_usage_millis === undefined && numbers.memory_usage_bytes === undefined && numbers.network_rx_bytes === undefined && numbers.pids_current === undefined)) invalid();
    if (Date.parse(started) > Date.parse(sampled)) invalid();
    return { sampled, started, reason: undefined };
  }
  if (sampled !== undefined || started !== undefined || Object.keys(numbers).length || reason === undefined) invalid();
  return { sampled: undefined, started: undefined, reason: enumValue(reason, ["not_running", "read_unavailable", "runtime_changed"]) };
}

export function managedImageMetricsDecoder(value: unknown, now = Date.now()): ManagedImageMetrics {
  const required = ["state", "available"];
  const row = exact(value, required, [...required, "unavailable_reason", "sampled_at", "process_started_at", ...metricFields]);
  const state = managedImageObservationDecoder({ state: row.state, source_limited: false }, now).state;
  const available = flag(row.available);
  const numbers = metricNumbers(row);
  const fields = metricAvailability(numbers, available, row.unavailable_reason, row.sampled_at, row.process_started_at);
  if (available && !state.running) invalid();
  if (!available && ((state.running && fields.reason === "not_running") || (!state.running && fields.reason !== "not_running"))) invalid();
  if (available && (now - Date.parse(fields.sampled!) > 40000 || Date.parse(fields.sampled!) > now + 30000)) invalid();
  return { state, available, unavailable_reason: fields.reason, sampled_at: fields.sampled, process_started_at: fields.started, ...numbers };
}

export function managedImageMetricsRecentDecoder(value: unknown, limit: number, now = Date.now()): ManagedImageMetricsRecent {
  const required = ["deployment_id", "container_id", "history_epoch", "current_segment_id", "scheduled", "selection_limited", "stale_after_seconds", "stale", "recording_status", "samples"];
  const row = exact(value, required, [...required, "history_start", "segment_start", "reason"]);
  const deployment_id = identifier(row.deployment_id), container_id = identifier(row.container_id), history_epoch = dateTime(row.history_epoch);
  const current_segment_id = metricNumber(row.current_segment_id, true), stale_after_seconds = metricNumber(row.stale_after_seconds, true);
  if (!(stale_after_seconds === 30 || (stale_after_seconds >= 40 && stale_after_seconds <= 250 && (stale_after_seconds - 40) % 15 === 0)) || !Array.isArray(row.samples) || row.samples.length > limit || row.samples.length > 360) invalid();
  const scheduled = flag(row.scheduled), selection_limited = flag(row.selection_limited), stale = flag(row.stale);
  const recording_status = enumValue(row.recording_status, ["not_selected", "warming_up", "recording", "stale"]);
  const reason = row.reason === undefined ? undefined : enumValue(row.reason, ["outside_sampling_selection", "first_sample_pending", "sample_expired", "read_failed", "not_running", "read_unavailable", "runtime_changed"]);
  const history_start = row.history_start === undefined ? undefined : dateTime(row.history_start);
  const segment_start = row.segment_start === undefined ? undefined : dateTime(row.segment_start);
  const count = row.samples.length;
  if (Date.parse(history_epoch) > now + 30000 ||
      (recording_status === "not_selected" && (scheduled || !stale || reason !== "outside_sampling_selection" || count !== 0)) ||
      (recording_status === "warming_up" && (!scheduled || !stale || reason !== "first_sample_pending" || count !== 0)) ||
      (recording_status === "recording" && (!scheduled || stale || reason !== undefined || count === 0)) ||
      (recording_status === "stale" && (!scheduled || !stale || !["sample_expired", "not_running", "read_unavailable", "runtime_changed", "read_failed"].includes(reason ?? "") || (count === 0 && reason !== "sample_expired" && reason !== "read_failed")))) invalid();
  if ((count === 0 && (current_segment_id !== 0 || history_start !== undefined || segment_start !== undefined)) ||
      (count > 0 && history_start === undefined)) invalid();
  let previousTime = -Infinity, previousSegment = 0, previousCID = "", previousStarted: string | undefined;
  const samples = row.samples.map((entry) => {
    const point = exact(entry, ["segment_id", "container_id", "observed_at", "available"], ["segment_id", "container_id", "process_started_at", "observed_at", "available", "unavailable_reason", ...metricFields]);
    const segment_id = metricNumber(point.segment_id, true), pointCID = identifier(point.container_id), observed_at = dateTime(point.observed_at), available = flag(point.available);
    const time = Date.parse(observed_at);
    if (!segment_id || segment_id < previousSegment || time <= previousTime || time < Date.parse(history_epoch) || time > now + 30000 || time < now - 31 * 60 * 1000) invalid();
    const numbers = metricNumbers(point);
    const process_started_at = metricTime(point.process_started_at);
    const unavailable_reason = point.unavailable_reason === undefined ? undefined : enumValue(point.unavailable_reason, ["not_running", "read_unavailable", "runtime_changed"]);
    if (available ? (!process_started_at || unavailable_reason !== undefined || (numbers.cpu_usage_millis === undefined && numbers.memory_usage_bytes === undefined && numbers.network_rx_bytes === undefined && numbers.pids_current === undefined)) : (Object.keys(numbers).length > 0 || !unavailable_reason || process_started_at !== undefined)) invalid();
    if (process_started_at && Date.parse(process_started_at) > time) invalid();
    if (segment_id === previousSegment && (pointCID !== previousCID || (process_started_at !== undefined && previousStarted !== undefined && process_started_at !== previousStarted))) invalid();
    if (segment_id !== previousSegment) { previousCID = pointCID; previousStarted = process_started_at; }
    else if (process_started_at !== undefined) previousStarted = process_started_at;
    previousTime = time; previousSegment = segment_id;
    return { segment_id, container_id: pointCID, observed_at, available, process_started_at, unavailable_reason, ...numbers };
  });
  if (samples.length && (current_segment_id !== samples[samples.length - 1].segment_id || (samples[samples.length - 1].container_id !== container_id && !stale) ||
      Date.parse(history_start!) < Date.parse(history_epoch) || Date.parse(history_start!) > Date.parse(samples[0].observed_at) ||
      (segment_start !== undefined && (Date.parse(segment_start) < Date.parse(history_epoch) || Date.parse(segment_start) > Date.parse(samples[samples.length - 1].observed_at))))) invalid();
  return { deployment_id, container_id, history_epoch, history_start, segment_start, current_segment_id, scheduled, selection_limited, stale_after_seconds, stale, recording_status, reason, samples };
}

export function imageDomainHostname(value: unknown): string {
  const host = text(value);
  if (host.length < 4 || host.length > 253 || host !== host.toLowerCase() || host.endsWith(".") ||
      ["localhost", ".localhost", ".local", ".internal"].some((suffix) => host === suffix || host.endsWith(suffix)) ||
      /^(?:\d{1,3}\.){3}\d{1,3}$/.test(host)) invalid("请输入规范的小写公网域名。");
  const labels = host.split(".");
  if (labels.length < 2 || labels.some((label) => label.length < 1 || label.length > 63 || !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label))) invalid("请输入规范的小写公网域名。");
  return host;
}

export function imageDomainOperationDecoder(value: unknown): ImageDomainOperation {
  const required = ["operation_id", "task_id", "approval_id", "deployment_id", "hostname", "action", "state", "created_at"];
  const row = exact(value, required, [...required, "reason", "result"]);
  const operation: ImageDomainOperation = {
    operation_id: identifier(row.operation_id), task_id: identifier(row.task_id), approval_id: identifier(row.approval_id),
    deployment_id: identifier(row.deployment_id), hostname: imageDomainHostname(row.hostname),
    action: enumValue(row.action, ["ensure", "remove"]), state: enumValue(row.state, ["pending", "running", "unknown", "succeeded", "failed"]),
    created_at: strictDateTime(row.created_at),
  };
  if (operation.state === "unknown" || operation.state === "failed") {
    const expected = operation.state === "unknown" ? "local route outcome requires reconciliation" : "local route command failed";
    if (row.reason !== expected || row.result !== undefined) invalid();
    operation.reason = expected;
  } else if (row.reason !== undefined) invalid();
  if (operation.state === "succeeded") {
    const result = exact(row.result, ["observed_at"], ["observed_at", "certificate_fingerprint", "certificate_expires_at"]);
    const observed_at = strictDateTime(result.observed_at);
    if (Date.parse(observed_at) < Date.parse(operation.created_at)) invalid();
    const certificate_fingerprint = result.certificate_fingerprint === undefined ? undefined : digest(result.certificate_fingerprint);
    const certificate_expires_at = result.certificate_expires_at === undefined ? undefined : strictDateTime(result.certificate_expires_at);
    if ((certificate_fingerprint === undefined) !== (certificate_expires_at === undefined) || (certificate_expires_at !== undefined && Date.parse(certificate_expires_at) <= Date.parse(observed_at))) invalid();
    operation.result = { observed_at, certificate_fingerprint, certificate_expires_at };
  } else if (row.result !== undefined) invalid();
  return operation;
}

export function imageDomainCurrentDecoder(value: unknown): ImageDomainCurrent {
  const row = exact(value, ["operation", "desired_public", "local_route_state", "deployment_status", "availability"]);
  const operation = imageDomainOperationDecoder(row.operation);
  const desired_public = flag(row.desired_public);
  const local_route_state = enumValue(row.local_route_state, ["desired", "configured", "reconcile_required", "disabled"]);
  const deployment_status = enumValue(row.deployment_status, ["running", "stopped", "deploying", "failed"]);
  const availability = enumValue(row.availability, ["pending", "degraded", "unverified", "disabled"]);
  const expected = local_route_state === "disabled" ? "disabled" :
    deployment_status !== "running" || local_route_state === "reconcile_required" || operation.state === "unknown" || operation.state === "failed" ? "degraded" :
      desired_public && local_route_state === "configured" && operation.state === "succeeded" ? "unverified" : "pending";
  if (availability !== expected) invalid();
  return { operation, desired_public, local_route_state, deployment_status, availability };
}

export function createCoreAuthClient(
  fetcher: Fetcher = fetch,
  onAuthenticationFailure?: (error: AcornFoxRequestError) => void,
): CoreAuthClient {
  const authFailure = (error: AcornFoxRequestError): AcornFoxRequestError => {
    if (error.kind === "authentication") onAuthenticationFailure?.(error);
    return error;
  };

  async function request<T>(
    path: string,
    decode: (value: unknown) => T,
    init: RequestInit = {},
    options: {
      csrf?: "mandatory" | "optional" | boolean;
      expectedStatus?: number;
      maxResponseBytes?: number;
    } = {},
  ): Promise<T> {
    const headers = new Headers(init.headers);
    if (init.body !== undefined) {
      headers.set("Content-Type", "application/json");
    }
    if (options.csrf === true || options.csrf === "mandatory") {
      const token = resolveCsrfToken();
      if (!token) {
        throw authFailure(
          new AcornFoxRequestError(
            401,
            "csrf_missing",
            "登录信息已失效，请重新登录。",
          ),
        );
      }
      headers.set("X-AcornFox-CSRF", token);
    } else if (options.csrf === "optional") {
      const token = resolveCsrfToken();
      if (token) {
        headers.set("X-AcornFox-CSRF", token);
      }
    }

    let result: Response;
    try {
      result = await fetcher(`${base}${path}`, {
        ...init,
        headers,
        credentials: "include",
        redirect: "error",
      });
    } catch (err: unknown) {
      if ((err as Error)?.name === "AbortError" || (err instanceof DOMException && err.name === "AbortError")) {
        throw err;
      }
      throw new AcornFoxRequestError(
        undefined,
        "network_error",
        "请求未完成，请检查连接后重试。",
      );
    }

    if (!result.ok) {
      if (init.signal?.aborted) {
        const abortErr = new Error("The operation was aborted");
        abortErr.name = "AbortError";
        throw abortErr;
      }
      let body: Record<string, unknown> | undefined;
      try {
        const parsed: unknown = await result.json();
        body =
          isRecord(parsed) &&
          Object.keys(parsed).every((key) => key === "code" || key === "message") &&
          typeof parsed.code === "string" &&
          typeof parsed.message === "string"
            ? parsed
            : undefined;
      } catch {
        /* empty error body */
      }
      if (init.signal?.aborted) {
        const abortErr = new Error("The operation was aborted");
        abortErr.name = "AbortError";
        throw abortErr;
      }
      const error = new AcornFoxRequestError(
        result.status,
        typeof body?.code === "string" ? body.code : `http_${result.status}`,
        typeof body?.message === "string"
          ? body.message
          : "请求未完成，请稍后重试。",
      );
      throw authFailure(error);
    }

    if (init.signal?.aborted) {
      const abortErr = new Error("The operation was aborted");
      abortErr.name = "AbortError";
      throw abortErr;
    }

    const expected = options.expectedStatus ?? (path === "/auth/logout" || path === "/auth/password" ? 204 : 200);
    if (result.status !== expected) return invalid();
    if (result.status === 204) return decode(undefined);

    try {
      let parsed: unknown;
      if (options.maxResponseBytes !== undefined) {
        const length = Number(result.headers.get("Content-Length"));
        if (Number.isFinite(length) && length > options.maxResponseBytes) invalid();
        const reader = result.body?.getReader();
        if (!reader) invalid();
        const parts: Uint8Array[] = []; let bytes = 0;
        try {
          while (true) {
            const chunk = await reader.read();
            if (chunk.done) break;
            bytes += chunk.value.byteLength;
            if (bytes > options.maxResponseBytes) { await reader.cancel(); invalid(); }
            parts.push(chunk.value);
          }
        } finally { reader.releaseLock(); }
        const buffer = new Uint8Array(bytes); let offset = 0;
        for (const part of parts) { buffer.set(part, offset); offset += part.length; }
        parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(buffer));
      } else parsed = await result.json();
      if (init.signal?.aborted) {
        const abortErr = new Error("The operation was aborted");
        abortErr.name = "AbortError";
        throw abortErr;
      }
      return decode(parsed);
    } catch (error) {
      if ((error as Error)?.name === "AbortError") throw error;
      if (error instanceof AcornFoxRequestError) throw error;
      return invalid();
    }
  }

  const json = (body: unknown) => JSON.stringify(body);
  const none = () => undefined;

  return {
    imageApps: (limit = 50, signal) => {
      if (!Number.isInteger(limit) || limit < 1 || limit > 100) return Promise.reject(new AcornFoxRequestError(422, "invalid_input", "列表数量必须在 1–100 之间。"));
      return request(`/image-apps?limit=${limit}`, managedImageApplicationsDecoder, { signal }, { expectedStatus: 200 });
    },
    createImagePlan: (input, signal) => request("/image-plans", imagePlanDecoder, { method: "POST", body: json(input), signal }, { csrf: "mandatory", expectedStatus: 201 }),
    imagePlan: (id, signal) => request(`/image-plans/${encodeURIComponent(identifier(id))}`, imagePlanDecoder, { signal }),
    confirmImagePlan: (input, signal) => request(`/image-plans/${encodeURIComponent(identifier(input.plan_id))}/confirm`, imageConfirmationDecoder, { method: "POST", body: json(input), signal }, { csrf: "mandatory" }),
    imageOperation: (id, signal) => request(`/operations/${encodeURIComponent(identifier(id))}`, imageOperationDecoder, { signal }),
    createImageLifecycle: (deploymentId, input, signal) => {
      const target = identifier(deploymentId);
      const action = enumValue(input.action, ["stop", "start", "restart"]);
      if (!input.idempotency_key.trim() || input.idempotency_key.length > 256) return Promise.reject(new AcornFoxRequestError(422, "invalid_input", "操作键不能为空。"));
      return request(`/image-deployments/${encodeURIComponent(target)}/lifecycle`, (value) => {
        const operation = imageLifecycleOperationDecoder(value);
        if (operation.deployment_id !== target || operation.action !== action || operation.state !== "pending" || operation.result !== undefined) invalid("操作响应与已提交意图不一致；请保留同一操作键核对。");
        return operation;
      }, { method: "POST", body: json(input), headers: { "Idempotency-Key": input.idempotency_key }, signal }, { csrf: "mandatory", expectedStatus: 200 });
    },
    imageLifecycleOperation: (id, signal) => {
      const target = identifier(id);
      return request(`/image-lifecycle-operations/${encodeURIComponent(target)}`, (value) => {
        const operation = imageLifecycleOperationDecoder(value);
        if (operation.operation_id !== target) invalid("操作响应与查询的操作 ID 不一致。");
        return operation;
      }, { signal }, { expectedStatus: 200 });
    },
    imageObservation: (deploymentId, signal) => request(`/image-deployments/${encodeURIComponent(identifier(deploymentId))}/observation`, (value) => {
      const sample = managedImageObservationDecoder(value);
      if (sample.records?.length) invalid();
      return sample;
    }, { signal, cache: "no-store" }, { expectedStatus: 200 }),
    imageLogs: (deploymentId, options = {}, signal) => {
      const tail = options.tail ?? 64;
      if (!Number.isInteger(tail) || tail < 1 || tail > 64) return Promise.reject(new AcornFoxRequestError(422, "invalid_input", "日志数量须在 1–64 之间。"));
      const query = new URLSearchParams({ tail: String(tail) });
      if (options.since !== undefined) {
        const since = Date.parse(options.since); const now = Date.now();
        if (!Number.isFinite(since) || since > now || since < now - 30 * 60 * 1000) return Promise.reject(new AcornFoxRequestError(422, "invalid_input", "日志起点须在最近 30 分钟内。"));
        query.set("since", new Date(since).toISOString());
      }
      return request(`/image-deployments/${encodeURIComponent(identifier(deploymentId))}/logs?${query}`, (value) => {
        const sample = managedImageObservationDecoder(value);
        if ((sample.records?.length ?? 0) > tail) invalid();
        return sample;
      }, { signal, cache: "no-store" }, { expectedStatus: 200 });
    },
    imageMetrics: (deploymentId, signal) => {
      const target = identifier(deploymentId);
      return request(`/image-deployments/${encodeURIComponent(target)}/metrics`, managedImageMetricsDecoder,
        { signal, cache: "no-store" }, { expectedStatus: 200, maxResponseBytes: 4096 });
    },
    imageMetricsRecent: (deploymentId, limit = 60, signal) => {
      const target = identifier(deploymentId);
      if (!Number.isInteger(limit) || limit < 1 || limit > 360) return Promise.reject(new AcornFoxRequestError(422, "invalid_input", "趋势样本数量须在 1–360 之间。"));
      return request(`/image-deployments/${encodeURIComponent(target)}/metrics/recent?limit=${limit}`,
        (value) => { const recent = managedImageMetricsRecentDecoder(value, limit); if (recent.deployment_id !== target) invalid(); return recent; },
        { signal, cache: "no-store" }, { expectedStatus: 200, maxResponseBytes: 256 * 1024 });
    },
    createImageDomainCommand: (deploymentId, input, signal) => {
      const target = identifier(deploymentId);
      let hostname: string;
      try { hostname = imageDomainHostname(input.hostname); }
      catch { return Promise.reject(new AcornFoxRequestError(422, "invalid_input", "请输入规范的小写公网域名。")); }
      const action = enumValue(input.action, ["ensure", "remove"]);
      const key = input.idempotency_key;
      if (!key || key !== key.trim() || key.length > 256) return Promise.reject(new AcornFoxRequestError(422, "invalid_input", "请保留原操作键，长度不超过 256 字符。"));
      return request(`/image-deployments/${encodeURIComponent(target)}/domain-commands`, (value) => {
        const operation = imageDomainOperationDecoder(value);
        if (operation.deployment_id !== target || operation.hostname !== hostname || operation.action !== action || operation.state !== "pending" || operation.result !== undefined) invalid("域名操作响应与原意图不一致；请保留同一操作键核对。");
        return operation;
      }, { method: "POST", body: json({ hostname, action, idempotency_key: key }), headers: { "Idempotency-Key": key }, signal }, { csrf: "mandatory", expectedStatus: 202 });
    },
    imageDomainCurrent: (deploymentId, signal) => {
      const target = identifier(deploymentId);
      return request(`/image-deployments/${encodeURIComponent(target)}/domain`, (value) => {
        const current = imageDomainCurrentDecoder(value);
        if (current.operation.deployment_id !== target) invalid("域名状态与当前受管部署不一致。");
        return current;
      }, { signal, cache: "no-store" }, { expectedStatus: 200 }).catch((error: unknown) => {
        if (error instanceof AcornFoxRequestError && error.status === 404 && error.code === "not_found") return null;
        throw error;
      });
    },
    imageDomainOperation: (operationId, signal) => {
      const target = identifier(operationId);
      return request(`/image-domain-operations/${encodeURIComponent(target)}`, (value) => {
        const operation = imageDomainOperationDecoder(value);
        if (operation.operation_id !== target) invalid("域名操作响应与查询 ID 不一致。");
        return operation;
      }, { signal, cache: "no-store" }, { expectedStatus: 200 });
    },
    setupState: () =>
      request("/setup", (value) =>
        enumValue(exact(value, ["state"]).state, ["initialized", "uninitialized", "unavailable"]),
      ),
    setup: ({ setupToken, password }) => {
      if (!setupToken || !password) {
        throw new AcornFoxRequestError(
          422,
          "invalid_input",
          "初始化令牌和管理员密码不能为空。",
        );
      }
      return request(
        "/setup",
        (value) => {
          const row = exact(value, ["initialized"]);
          return row.initialized === true ? undefined : invalid();
        },
        {
          method: "POST",
          body: json({ setup_token: setupToken, password }),
        },
        { csrf: "optional", expectedStatus: 201 },
      );
    },
    login: (password) => {
      if (!password) {
        throw new AcornFoxRequestError(422, "invalid_input", "请输入管理员密码。");
      }
      return request(
        "/auth/login",
        sessionDecoder,
        {
          method: "POST",
          body: json({ password }),
        },
        { expectedStatus: 200 },
      );
    },
    logout: () =>
      request("/auth/logout", none, { method: "POST" }, { csrf: true, expectedStatus: 204 }),
    session: () => request("/auth/session", sessionDecoder, {}, { expectedStatus: 200 }),
    changePassword: (currentPassword, newPassword) => {
      if (!currentPassword || !newPassword) {
        throw new AcornFoxRequestError(
          422,
          "invalid_input",
          "当前密码和新密码不能为空。",
        );
      }
      return request(
        "/auth/password",
        none,
        {
          method: "POST",
          body: json({ current_password: currentPassword, new_password: newPassword }),
        },
        { csrf: true, expectedStatus: 204 },
      );
    },
    coreStatus: () =>
      request("/core/status", coreStatusDecoder, {}, { expectedStatus: 200 }),
    hostMetrics: (signal) =>
      request(
        "/host/metrics",
        hostMetricsDecoder,
        { method: "GET", signal },
        { expectedStatus: 200 },
      ),
    hostMetricsRecent: (limit = 60, signal) => {
      if (!Number.isInteger(limit) || limit < 1 || limit > 360) {
        throw new AcornFoxRequestError(
          400,
          "bad_request",
          "limit 参数必须为 1 至 360 之间的整数。",
        );
      }
      const path = limit === 60 ? "/host/metrics/recent" : `/host/metrics/recent?limit=${limit}`;
      return request(
        path,
        (val) => hostMetricsRecentDecoder(val, limit),
        { method: "GET", signal },
        { expectedStatus: 200 },
      );
    },
  };
}
