import type { components } from "../api/acornfox-generated-schema";
import { resolveCsrfToken } from "./csrf";

export type AcornFoxSchemas = components["schemas"];
export type Application = AcornFoxSchemas["Application"];
export type SourceRevision = AcornFoxSchemas["SourceRevision"];
export type Deployment = AcornFoxSchemas["DeploymentRuntimeState"];
export type DeliveryStatus = AcornFoxSchemas["DeliveryStatusResponse"];
export type DeliveryLogs = AcornFoxSchemas["DeliveryLogsResponse"];
export type PublicAccess = AcornFoxSchemas["PublicAccessResponse"];
export type Session = AcornFoxSchemas["AuthSessionResponse"];
export type Command = AcornFoxSchemas["DeliveryCommandResponse"];
export type Page<T> = { items: T[]; nextCursor?: string };
export type LogsPage = Page<DeliveryLogs["items"][number]> &
  Pick<DeliveryLogs, "source" | "availability" | "retention_limited">;

const base = "/api/v1/acornfox";
type Fetcher = (
  input: RequestInfo | URL,
  init?: RequestInit,
) => Promise<Response>;
type Value = Record<string, unknown>;
type AuthFailure = (error: AcornFoxRequestError) => void;

export function expectedSuccessStatus(path: string, method = "GET"): number {
  const normalized = method.toUpperCase();
  if (path === "/auth/logout" || path === "/auth/password") return 204;
  if (path === "/apps" && normalized === "POST") return 201;
  if (path.endsWith("/restart") || path.endsWith("/redeploy") || path.endsWith("/probes")) return 202;
  if (/\/apps\/[^/]+\/deliveries$/.test(path) && normalized === "POST")
    return 202;
  return 200;
}

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

export interface AcornFoxClient {
  login(password: string): Promise<Session>;
  logout(): Promise<void>;
  session(): Promise<Session>;
  changePassword(currentPassword: string, newPassword: string): Promise<void>;
  apps(): Promise<Application[]>;
  app(id: string): Promise<Application>;
  createApp(input: {
    name: string;
    repositoryUrl: string;
    ref: string;
  }): Promise<{
    application: Application;
    sourceRevisionId: string;
    operationId: string;
  }>;
  sources(
    applicationId: string,
    cursor?: string,
  ): Promise<Page<SourceRevision>>;
  source(applicationId: string, sourceId: string): Promise<SourceRevision>;
  deployments(
    applicationId: string,
    cursor?: string,
  ): Promise<Page<Deployment>>;
  deploy(
    applicationId: string,
    sourceId: string,
    port?: number,
  ): Promise<Command>;
  status(applicationId: string, deploymentId: string): Promise<DeliveryStatus>;
  logs(
    applicationId: string,
    deploymentId: string,
    source: "build" | "runtime",
    cursor?: string,
  ): Promise<LogsPage>;
  probe(applicationId: string, deploymentId: string): Promise<Command>;
  restart(applicationId: string, deploymentId: string): Promise<Command>;
  redeploy(applicationId: string, deploymentId: string): Promise<Command>;
  publicAccess(
    applicationId: string,
    deploymentId: string,
  ): Promise<PublicAccess>;
  setPublicAccess(
    applicationId: string,
    deploymentId: string,
    enabled: boolean,
  ): Promise<PublicAccess>;
}

function isRecord(value: unknown): value is Value {
  return typeof value === "object" && value !== null;
}
function invalid(): never {
  throw new AcornFoxRequestError(
    undefined,
    "invalid_response",
    "服务返回的数据无法识别。",
  );
}
function record(value: unknown): Value {
  return isRecord(value) ? value : invalid();
}
function text(value: unknown): string {
  return typeof value === "string" ? value : invalid();
}
function flag(value: unknown): boolean {
  return typeof value === "boolean" ? value : invalid();
}
function numberValue(value: unknown): number {
  return typeof value === "number" && Number.isFinite(value)
    ? value
    : invalid();
}
function maybeText(value: unknown): string | undefined {
  return value === undefined ? undefined : text(value);
}
function maybeNumber(value: unknown): number | undefined {
  return value === undefined ? undefined : numberValue(value);
}
function isOneOf<T extends string>(
  value: unknown,
  choices: readonly T[],
): value is T {
  return (
    typeof value === "string" && choices.some((choice) => choice === value)
  );
}
function enumValue<T extends string>(value: unknown, choices: readonly T[]): T {
  return isOneOf(value, choices) ? value : invalid();
}
function exact(
  value: unknown,
  mandatory: readonly string[],
  allowed: readonly string[] = mandatory,
): Value {
  const row = record(value);
  if (!mandatory.every((key) => Object.hasOwn(row, key))) return invalid();
  if (!Object.keys(row).every((key) => allowed.includes(key))) return invalid();
  return row;
}
function dateTime(value: unknown): string {
  const result = text(value);
  return /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/.test(
    result,
  ) && !Number.isNaN(Date.parse(result))
    ? result
    : invalid();
}
function integer(value: unknown): number {
  return Number.isInteger(value) ? numberValue(value) : invalid();
}
function httpsUri(value: unknown): string {
  const result = text(value);
  try {
    const parsed = new URL(result);
    return parsed.protocol === "https:" &&
      parsed.host.length > 0 &&
      parsed.username === "" &&
      parsed.password === ""
      ? result
      : invalid();
  } catch {
    return invalid();
  }
}

function application(value: unknown): Application {
  const row = exact(value, ["id", "name", "created_at", "updated_at"]);
  return {
    id: text(row.id),
    name: text(row.name),
    created_at: dateTime(row.created_at),
    updated_at: dateTime(row.updated_at),
  };
}
function applicationList(value: unknown): Application[] {
  const row = exact(value, ["items"]);
  return Array.isArray(row.items) ? row.items.map(application) : invalid();
}
function source(value: unknown): SourceRevision {
  const row = exact(
    value,
    [
      "id",
      "application_id",
      "kind",
      "locator_sha256",
      "content_digest",
      "created_at",
      "immutable",
    ],
    [
      "id",
      "application_id",
      "kind",
      "locator_sha256",
      "ref",
      "commit",
      "content_digest",
      "created_at",
      "immutable",
    ],
  );
  return {
    id: text(row.id),
    application_id: text(row.application_id),
    kind: enumValue(row.kind, ["git_https"]),
    locator_sha256: text(row.locator_sha256),
    ref: maybeText(row.ref),
    commit: maybeText(row.commit),
    content_digest: text(row.content_digest),
    created_at: dateTime(row.created_at),
    immutable: flag(row.immutable),
  };
}
function deployment(value: unknown): Deployment {
  const row = exact(value, [
    "id",
    "application_id",
    "environment_id",
    "release_id",
    "stage",
    "created_at",
    "updated_at",
  ]);
  return {
    id: text(row.id),
    application_id: text(row.application_id),
    environment_id: text(row.environment_id),
    release_id: text(row.release_id),
    stage: enumValue(row.stage, [
      "starting",
      "runtime_observed",
      "failed",
      "unknown",
    ]),
    created_at: dateTime(row.created_at),
    updated_at: dateTime(row.updated_at),
  };
}
function command(value: unknown): Command {
  const row = exact(value, [
    "deployment_id",
    "operation_id",
    "task_id",
    "status",
  ]);
  return {
    deployment_id: text(row.deployment_id),
    operation_id: text(row.operation_id),
    task_id: text(row.task_id),
    status: text(row.status),
  };
}
function session(value: unknown): Session {
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
function requested(
  value: unknown,
): NonNullable<DeliveryStatus["desired"]>["resources"] {
  const row = exact(value, [
    "cpu_millis",
    "memory_bytes",
    "pids",
    "disk_reservation_bytes",
  ]);
  return {
    cpu_millis: integer(row.cpu_millis),
    memory_bytes: integer(row.memory_bytes),
    pids: integer(row.pids),
    disk_reservation_bytes: integer(row.disk_reservation_bytes),
  };
}
function desired(value: unknown): NonNullable<DeliveryStatus["desired"]> {
  const row = exact(
    value,
    [
      "application_id",
      "environment_id",
      "release_id",
      "service_name",
      "image",
      "resources",
      "accepted_at",
      "immutable",
    ],
    [
      "application_id",
      "environment_id",
      "release_id",
      "service_name",
      "image",
      "resources",
      "container_port",
      "accepted_at",
      "immutable",
    ],
  );
  const image = exact(row.image, ["repository", "digest"]);
  const port = maybeNumber(row.container_port);
  if (
    port !== undefined &&
    (!Number.isInteger(port) || port < 0 || port > 65535)
  )
    invalid();
  return {
    application_id: text(row.application_id),
    environment_id: text(row.environment_id),
    release_id: text(row.release_id),
    service_name: text(row.service_name),
    image: { repository: text(image.repository), digest: text(image.digest) },
    resources: requested(row.resources),
    ...(port === undefined ? {} : { container_port: port }),
    accepted_at: dateTime(row.accepted_at),
    immutable: flag(row.immutable),
  };
}
function runtime(value: unknown): NonNullable<DeliveryStatus["runtime"]> {
  const row = exact(
    value,
    [
      "deployment_id",
      "service_name",
      "runtime_state",
      "restart_count",
      "requested_resources",
      "applied_limits",
      "disk",
      "observed_at",
    ],
    [
      "deployment_id",
      "service_name",
      "container_id",
      "runtime_state",
      "restart_count",
      "internal_address",
      "requested_resources",
      "applied_limits",
      "disk",
      "observed_at",
    ],
  );
  const limits = exact(row.applied_limits, [
    "cpu_millis",
    "memory_bytes",
    "pids",
  ]);
  const disk = exact(row.disk, [
    "reservation_bytes",
    "accounting_reconciled",
    "per_container_enforced",
  ]);
  const container = maybeText(row.container_id);
  const address = maybeText(row.internal_address);
  return {
    deployment_id: text(row.deployment_id),
    service_name: text(row.service_name),
    ...(container === undefined ? {} : { container_id: container }),
    runtime_state: text(row.runtime_state),
    restart_count: integer(row.restart_count),
    ...(address === undefined ? {} : { internal_address: address }),
    requested_resources: requested(row.requested_resources),
    applied_limits: {
      cpu_millis: integer(limits.cpu_millis),
      memory_bytes: integer(limits.memory_bytes),
      pids: integer(limits.pids),
    },
    disk: {
      reservation_bytes: integer(disk.reservation_bytes),
      accounting_reconciled: flag(disk.accounting_reconciled),
      per_container_enforced: flag(disk.per_container_enforced),
    },
    observed_at: dateTime(row.observed_at),
  };
}
function responseFact(value: unknown): NonNullable<DeliveryStatus["response"]> {
  const row = exact(
    value,
    ["protocol", "outcome", "observed_at", "fact_digest"],
    [
      "protocol",
      "outcome",
      "http_status",
      "latency_ms",
      "error_code",
      "observed_at",
      "fact_digest",
    ],
  );
  const http = row.http_status;
  if (
    http !== undefined &&
    http !== null &&
    (typeof http !== "number" ||
      !Number.isInteger(http) ||
      http < 100 ||
      http > 599)
  )
    invalid();
  return {
    protocol: enumValue(row.protocol, ["tcp", "http"]),
    outcome: text(row.outcome),
    ...(http === undefined
      ? {}
      : { http_status: http === null ? null : integer(http) }),
    ...(row.latency_ms === undefined
      ? {}
      : { latency_ms: integer(row.latency_ms) }),
    ...(row.error_code === undefined
      ? {}
      : { error_code: text(row.error_code) }),
    observed_at: dateTime(row.observed_at),
    fact_digest: text(row.fact_digest),
  };
}
function deliveryStatus(value: unknown): DeliveryStatus {
  const row = exact(value, ["deployment", "desired", "runtime", "response"]);
  return {
    deployment: deployment(row.deployment),
    desired: row.desired === null ? null : desired(row.desired),
    runtime: row.runtime === null ? null : runtime(row.runtime),
    response: row.response === null ? null : responseFact(row.response),
  };
}
function logs(value: unknown): DeliveryLogs {
  const row = exact(value, [
    "source",
    "availability",
    "items",
    "next_cursor",
    "retention_limited",
  ]);
  if (!Array.isArray(row.items)) return invalid();
  return {
    source: enumValue(row.source, ["build", "runtime"]),
    availability: enumValue(row.availability, [
      "available",
      "not_collected",
      "retired",
    ]),
    items: row.items.map((entry) => {
      const item = exact(entry, [
        "stream",
        "recorded_at",
        "content",
        "truncation",
      ]);
      return {
        stream: enumValue(item.stream, [
          "stdout",
          "stderr",
          "combined",
          "unknown",
        ]),
        recorded_at: dateTime(item.recorded_at),
        content: text(item.content),
        truncation: enumValue(item.truncation, [
          "complete",
          "source_limited",
          "response_limited",
          "unknown",
        ]),
      };
    }),
    next_cursor: row.next_cursor === null ? null : text(row.next_cursor),
    retention_limited: flag(row.retention_limited),
  };
}
function publicAccess(value: unknown): PublicAccess {
  const row = exact(value, [
    "desired_public",
    "url",
    "endpoint",
    "components",
    "status",
  ]);
  const endpoint = exact(row.endpoint, ["deployment_id"]);
  const details = exact(row.components, [
    "internal_endpoint",
    "local_route",
    "dns",
    "tls",
    "external",
  ]);
  return {
    desired_public: flag(row.desired_public),
    url: httpsUri(row.url),
    endpoint: { deployment_id: text(endpoint.deployment_id) },
    components: {
      internal_endpoint: enumValue(details.internal_endpoint, [
        "accepted",
        "not_observed",
      ]),
      local_route: enumValue(details.local_route, [
        "desired",
        "reconcile_required",
        "configured",
        "disabled",
      ]),
      dns: enumValue(details.dns, ["not_validated"]),
      tls: enumValue(details.tls, ["not_validated"]),
      external: enumValue(details.external, ["not_validated"]),
    },
    status: enumValue(row.status, [
      "PUBLIC_DISABLED",
      "PENDING_EXTERNAL_VALIDATION",
    ]),
  };
}
function discoveryPage<T>(
  value: unknown,
  parse: (item: unknown) => T,
): Page<T> {
  const root = exact(value, ["items", "next_cursor"]);
  if (!Array.isArray(root.items)) return invalid();
  if (root.next_cursor !== null && typeof root.next_cursor !== "string")
    return invalid();
  return {
    items: root.items.map(parse),
    ...(root.next_cursor === null ? {} : { nextCursor: root.next_cursor }),
  };
}

function csrfCookie(): string | undefined {
  return resolveCsrfToken();
}
function idempotencyKey(): string {
  if (typeof crypto === "undefined") invalid();
  if (typeof crypto.randomUUID === "function") return crypto.randomUUID();
  if (typeof crypto.getRandomValues !== "function") invalid();
  return Array.from(crypto.getRandomValues(new Uint8Array(16)), (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("");
}
function pathPart(value: string): string {
  return encodeURIComponent(value);
}
function inputError(message: string): never {
  throw new AcornFoxRequestError(422, "invalid_input", message);
}
function publicRepository(value: string): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return inputError("仓库地址必须是公开 HTTPS Git 地址。");
  }
  return url.protocol === "https:" && url.username === "" && url.password === ""
    ? value
    : inputError("仓库地址必须是公开 HTTPS Git 地址。");
}

export function createAcornFoxClient(
  fetcher: Fetcher = fetch,
  onAuthenticationFailure?: AuthFailure,
): AcornFoxClient {
  const authFailure = (error: AcornFoxRequestError): AcornFoxRequestError => {
    if (error.kind === "authentication") onAuthenticationFailure?.(error);
    return error;
  };
  async function request<T>(
    path: string,
    decode: (value: unknown) => T,
    init: RequestInit = {},
    options: { csrf?: boolean; idempotency?: boolean } = {},
  ): Promise<T> {
    const headers = new Headers(init.headers);
    if (init.body !== undefined)
      headers.set("Content-Type", "application/json");
    if (options.csrf) {
      const token = csrfCookie();
      if (!token)
        throw authFailure(
          new AcornFoxRequestError(
            401,
            "csrf_missing",
            "登录信息已失效，请重新登录。",
          ),
        );
      headers.set("X-AcornFox-CSRF", token);
    }
    if (options.idempotency) headers.set("Idempotency-Key", idempotencyKey());
    let result: Response;
    try {
      result = await fetcher(`${base}${path}`, {
        ...init,
        headers,
        credentials: "include",
        redirect: "error",
      });
    } catch {
      throw new AcornFoxRequestError(
        undefined,
        "network_error",
        "请求未完成，请检查连接后重试。",
      );
    }
    if (!result.ok) {
      let body: Value | undefined;
      try {
        const parsed: unknown = await result.json();
        body =
          isRecord(parsed) &&
          Object.keys(parsed).every(
            (key) => key === "code" || key === "message",
          ) &&
          typeof parsed.code === "string" &&
          typeof parsed.message === "string"
            ? parsed
            : undefined;
      } catch {
        /* empty error body */
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
    if (result.status !== expectedSuccessStatus(path, init.method))
      return invalid();
    if (result.status === 204) return decode(undefined);
    try {
      const parsed: unknown = await result.json();
      return decode(parsed);
    } catch (error) {
      if (error instanceof AcornFoxRequestError) throw error;
      return invalid();
    }
  }
  const json = (body: unknown) => JSON.stringify(body);
  const write = { csrf: true, idempotency: true };
  const none = () => undefined;
  return {
    login: (password) =>
      password
        ? request("/auth/login", session, {
            method: "POST",
            body: json({ password }),
          })
        : inputError("请输入管理员密码。"),
    logout: () =>
      request("/auth/logout", none, { method: "POST" }, { csrf: true }),
    session: () => request("/auth/session", session),
    changePassword: (current_password, new_password) =>
      current_password && new_password
        ? request(
            "/auth/password",
            none,
            { method: "POST", body: json({ current_password, new_password }) },
            { csrf: true },
          )
        : inputError("当前密码和新密码不能为空。"),
    apps: () => request("/apps", applicationList),
    app: (id) => request(`/apps/${pathPart(id)}`, application),
    createApp: async ({ name, repositoryUrl, ref }) => {
      if (!name.trim()) inputError("应用名称不能为空。");
      if (!ref.trim()) inputError("版本引用不能为空。");
      return request(
        "/apps",
        (value) => {
          const row = exact(value, [
            "application",
            "source_revision_id",
            "operation_id",
          ]);
          return {
            application: application(row.application),
            sourceRevisionId: text(row.source_revision_id),
            operationId: text(row.operation_id),
          };
        },
        {
          method: "POST",
          body: json({
            name: name.trim(),
            source: {
              type: "public_git",
              repository_url: publicRepository(repositoryUrl),
              ref: ref.trim(),
            },
          }),
        },
        write,
      );
    },
    sources: (id, cursor) =>
      request(
        `/apps/${pathPart(id)}/sources?limit=50${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ""}`,
        (value) => discoveryPage(value, source),
      ),
    source: (id, sourceId) =>
      request(`/apps/${pathPart(id)}/sources/${pathPart(sourceId)}`, source),
    deployments: (id, cursor) =>
      request(
        `/apps/${pathPart(id)}/deliveries?limit=50${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ""}`,
        (value) => discoveryPage(value, deployment),
      ),
    deploy: (id, sourceId, port) => {
      if (
        port !== undefined &&
        (!Number.isInteger(port) || port < 0 || port > 65535)
      )
        inputError("端口必须是 0 到 65535 的整数。");
      return request(
        `/apps/${pathPart(id)}/deliveries`,
        command,
        {
          method: "POST",
          body: json({
            source_revision_id: sourceId,
            ...(port === undefined ? {} : { container_port: port }),
          }),
        },
        write,
      );
    },
    status: (id, deploymentId) =>
      request(
        `/apps/${pathPart(id)}/deliveries/${pathPart(deploymentId)}`,
        deliveryStatus,
      ),
    logs: (id, deploymentId, logSource, cursor) =>
      request(
        `/apps/${pathPart(id)}/deliveries/${pathPart(deploymentId)}/logs?source=${logSource}&limit=50${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ""}`,
        (value) => {
          const page = logs(value);
          return {
            items: page.items,
            ...(page.next_cursor === null
              ? {}
              : { nextCursor: page.next_cursor }),
            source: page.source,
            availability: page.availability,
            retention_limited: page.retention_limited,
          };
        },
      ),
    probe: (id, deploymentId) =>
      request(
        `/apps/${pathPart(id)}/deliveries/${pathPart(deploymentId)}/probes`,
        command,
        { method: "POST", body: json({ protocol: "http", path: "/" }) },
        write,
      ),
    restart: (id, deploymentId) =>
      request(
        `/apps/${pathPart(id)}/deliveries/${pathPart(deploymentId)}/restart`,
        command,
        { method: "POST", body: json({}) },
        write,
      ),
    redeploy: (id, deploymentId) =>
      request(
        `/apps/${pathPart(id)}/deliveries/${pathPart(deploymentId)}/redeploy`,
        command,
        { method: "POST", body: json({}) },
        write,
      ),
    publicAccess: (id, deploymentId) =>
      request(
        `/apps/${pathPart(id)}/deliveries/${pathPart(deploymentId)}/public-access`,
        publicAccess,
      ),
    setPublicAccess: (id, deploymentId, enabled) =>
      request(
        `/apps/${pathPart(id)}/deliveries/${pathPart(deploymentId)}/public-access`,
        publicAccess,
        { method: "PUT", body: json({ enabled }) },
        write,
      ),
  };
}
