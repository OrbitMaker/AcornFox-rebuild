import { AcornFoxRequestError, type Command } from "./client";

type CandidateBase = {
  candidate_id: string;
  application_id: string;
  base_source_revision_id: string;
  created_at: string;
};
type Image = { repository: string; digest: string; resolved_tag?: string };
export type ValidatedFixCandidate = CandidateBase & {
  status: "validated" | "source_matched";
  base_repository_url: string;
  base_commit: string;
  base_tree_digest: string;
  patch_digest: string;
  result_tree_digest: string;
  container_port: number;
  changed_paths: string[];
  canonical_diff: string;
  validated_image: Image;
  build_log_ref: string;
  build_evidence_digest: string;
  runtime: {
    task_id: string; image: Image; runtime_state: "stopped"; probe_outcome: "responded";
    http_status?: number; cleanup_confirmed: true; evidence_digest: string;
  };
  matched_source_revision_id?: string;
  matched_commit?: string;
  expires_at: string;
};
export type FixCandidate = (CandidateBase & { status: "preparing" | "failed" }) | ValidatedFixCandidate;
export interface FixCandidateClient {
  list(appId: string): Promise<FixCandidate[]>;
  get(appId: string, candidateId: string): Promise<FixCandidate>;
  match(appId: string, candidateId: string, sourceId: string): Promise<ValidatedFixCandidate>;
  publish(appId: string, candidateId: string, key: string): Promise<Command>;
}
type Fetcher = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;
type Row = Record<string, unknown>;
const bad = (): never => { throw new AcornFoxRequestError(undefined, "invalid_response", "修复候选数据无法核验，请刷新事实。"); };
function row(value: unknown): Row { return typeof value === "object" && value !== null && !Array.isArray(value) ? value as Row : bad(); }
function text(value: unknown): string { return typeof value === "string" && value.length > 0 ? value : bad(); }
function digest(value: unknown): string { const result = text(value); return /^sha256:[0-9a-f]{64}$/.test(result) ? result : bad(); }
function commit(value: unknown): string { const result = text(value); return /^[0-9a-f]{40}([0-9a-f]{24})?$/.test(result) ? result : bad(); }
function date(value: unknown): string { const result = text(value); return /^\d{4}-\d{2}-\d{2}T/.test(result) && Number.isFinite(Date.parse(result)) ? result : bad(); }
function image(value: unknown): Image { const valueRow = row(value); return { repository: text(valueRow.repository), digest: digest(valueRow.digest), ...(valueRow.resolved_tag === undefined ? {} : { resolved_tag: text(valueRow.resolved_tag) }) }; }
export function decodeFixCandidate(value: unknown, appId: string): FixCandidate {
  const data = row(value);
  const base = { candidate_id: text(data.candidate_id), application_id: text(data.application_id), base_source_revision_id: text(data.base_source_revision_id), created_at: date(data.created_at) };
  if (base.application_id !== appId || !/^candidate_[0-9a-f]{32}$/.test(base.candidate_id)) return bad();
  if (data.status === "preparing" || data.status === "failed") return { ...base, status: data.status };
  if (data.status !== "validated" && data.status !== "source_matched") return bad();
  const runtime = row(data.runtime), validatedImage = image(data.validated_image), runtimeImage = image(runtime.image);
  if (runtime.runtime_state !== "stopped" || runtime.probe_outcome !== "responded" || runtime.cleanup_confirmed !== true || runtimeImage.repository !== validatedImage.repository || runtimeImage.digest !== validatedImage.digest) return bad();
  const http = runtime.http_status;
  if (http !== undefined && (typeof http !== "number" || !Number.isInteger(http) || http < 100 || http > 599)) return bad();
  if (!Array.isArray(data.changed_paths) || !data.changed_paths.length || data.changed_paths.length > 32) return bad();
  const changedPaths = data.changed_paths.map(text), diff = text(data.canonical_diff), expires = date(data.expires_at);
  if (new TextEncoder().encode(diff).length > 128 * 1024 || Date.parse(expires) <= Date.parse(base.created_at)) return bad();
  if (typeof data.container_port !== "number" || !Number.isInteger(data.container_port) || data.container_port < 1 || data.container_port > 65535) return bad();
  const repository = text(data.base_repository_url);
  try { const url = new URL(repository); if (url.protocol !== "https:" || url.username || url.password) return bad(); } catch { return bad(); }
  const matched = data.status === "source_matched" ? { matched_source_revision_id: text(data.matched_source_revision_id), matched_commit: commit(data.matched_commit) } : {};
  if (data.status === "validated" && (data.matched_source_revision_id !== undefined || data.matched_commit !== undefined)) return bad();
  return { ...base, status: data.status, base_repository_url: repository, base_commit: commit(data.base_commit), base_tree_digest: digest(data.base_tree_digest), patch_digest: digest(data.patch_digest), result_tree_digest: digest(data.result_tree_digest), container_port: data.container_port, changed_paths: changedPaths, canonical_diff: diff, validated_image: validatedImage, build_log_ref: text(data.build_log_ref), build_evidence_digest: digest(data.build_evidence_digest), runtime: { task_id: text(runtime.task_id), image: runtimeImage, runtime_state: "stopped", probe_outcome: "responded", cleanup_confirmed: true, evidence_digest: digest(runtime.evidence_digest), ...(http === undefined ? {} : { http_status: http as number }) }, ...matched, expires_at: expires };
}

// The UI uses one logical publication key per candidate, including after a reload.
export function candidatePublishKey(appId: string, candidateId: string): string { return `fix-publish:${appId}:${candidateId}`; }

export function createFixCandidateClient(fetcher: Fetcher = fetch): FixCandidateClient {
  const path = (appId: string, candidateId?: string) => `/api/v1/acornfox/apps/${encodeURIComponent(appId)}/fix-candidates${candidateId ? `/${encodeURIComponent(candidateId)}` : ""}`;
  async function request(url: string, expected: number, init: RequestInit = {}): Promise<unknown> {
    const headers = new Headers(init.headers); headers.set("Accept", "application/json");
    if (init.method === "POST") {
      const cookie = typeof document === "undefined" ? undefined : document.cookie.split(";").map((part) => part.trim()).find((part) => part.startsWith("__Host-acornfox_csrf="));
      let token: string | undefined; try { token = cookie ? decodeURIComponent(cookie.slice("__Host-acornfox_csrf=".length)) : undefined; } catch { /* malformed cookie is not authorization */ }
      if (!token) throw new AcornFoxRequestError(401, "csrf_missing", "登录已过期，请重新登录。");
      headers.set("X-AcornFox-CSRF", token);
      if (init.body !== undefined) headers.set("Content-Type", "application/json");
    }
    let response: Response;
    try { response = await fetcher(url, { ...init, headers, credentials: "include", redirect: "error" }); } catch { throw new AcornFoxRequestError(undefined, "network_error", "请求结果尚未确认。"); }
    let body: unknown; try { body = await response.json(); } catch { return bad(); }
    if (response.status !== expected) { const error = row(body); throw new AcornFoxRequestError(response.status, typeof error.code === "string" ? error.code : "request_failed", "请求未完成，请刷新事实。"); }
    return body;
  }
  const decode = (value: unknown, appId: string, candidateId: string) => { const result = decodeFixCandidate(value, appId); return result.candidate_id === candidateId ? result : bad(); };
  return {
    async list(appId) { const data = row(await request(path(appId), 200)); if (!Array.isArray(data.items) || data.items.length > 50) return bad(); const items = data.items.map((item) => decodeFixCandidate(item, appId)); if (new Set(items.map((item) => item.candidate_id)).size !== items.length) return bad(); return items; },
    async get(appId, candidateId) { return decode(await request(path(appId, candidateId), 200), appId, candidateId); },
    async match(appId, candidateId, sourceId) { const result = decode(await request(`${path(appId, candidateId)}/source-match`, 200, { method: "POST", body: JSON.stringify({ source_revision_id: sourceId }) }), appId, candidateId); return result.status === "source_matched" && result.matched_source_revision_id === sourceId ? result as ValidatedFixCandidate : bad(); },
    async publish(appId, candidateId, key) { const data = row(await request(`${path(appId, candidateId)}/publish`, 202, { method: "POST", headers: { "Idempotency-Key": key } })); if (data.status !== "accepted") return bad(); return { deployment_id: text(data.deployment_id), operation_id: text(data.operation_id), task_id: text(data.task_id), status: text(data.status) }; },
  };
}
