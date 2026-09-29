import {
  applyPublishingEvent,
  createPublishingSnapshot,
  isPublishEventKind,
  isPublishingStatus,
  type PublishEvent,
} from '../domain/publishing';
import type {
  ApiClient,
  ApplicationSource,
  ApplicationListResponse,
  ApplicationSummary,
  ApplicationOperationsResult,
  ApplicationUsageResult,
  CreateApplicationSource,
  CreateApplicationInput,
  CreateApplicationResponse,
  OperationRequestResult,
  PublishEventListener,
  AccessRouteStatus,
  ApplicationAccessResponse,
  ApplicationPublishInput,
  ApplicationPublishResponse,
  ApplicationDetail,
  ApplicationDomain,
  ApplicationDomainResponse,
  ApplicationDomainUnbindOperation,
  ApplicationDomainUnbindResponse,
  ApplicationDomainsResponse,
  CertificateStatus,
  CustomDomainBindRequest,
  DomainVerification,
  FailureState,
  PlatformDomainSettingsRequest,
  PlatformDomainSettingsResponse,
  SourceUploadInput,
  SourceUploadManifest,
  SourceUploadManifestEntry,
  SourceUploadResponse,
  SystemStatusFact,
  SystemStatusResult,
  PublishConnectionState,
} from './types';
import { CSRF_COOKIE_NAME, CSRF_HEADER_NAME, type AuthLoginInput, type AuthSession, type PasswordChangeInput } from '../features/auth/auth';
import type { ApplicationUsageFact, UsageAnomaly, UsageMeasurement, UsageResourceMeasurements, UsageServiceFact, UsageTrendPoint } from '../features/usage/usageFacts';
import type { DomainAccessSnapshot } from '../features/domains/domainAccess';
import type {
  ApplicationOperationsFact,
  OperationAction,
  OperationActionFact,
  OperationActionStatus,
  OperationRequest,
  ServiceHealth,
  ServiceOperationsFact,
} from '../features/operations/operationsView';
import {
  ApiRequestError,
  createNetworkError,
  createResponseError,
  createTimeoutError,
} from './errors';

export { ApiRequestError } from './errors';

const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL as string | undefined) ?? '/api/v1';
const DEFAULT_TIMEOUT_MS = 15_000;
const SSE_RETRY_DELAYS_MS = [1_000, 2_000, 5_000, 10_000, 30_000] as const;

type EventSourceRequestInit = EventSourceInit & { lastEventId?: string };
type EventSourceLike = Pick<EventSource, 'addEventListener' | 'removeEventListener' | 'close'> & {
  onerror?: ((event: Event) => void) | null;
  onopen?: ((event: Event) => void) | null;
};

type EventSourceFactory = (url: string, init?: EventSourceRequestInit) => EventSourceLike;

function isWriteMethod(method: string | undefined): boolean {
  return ['POST', 'PUT', 'PATCH', 'DELETE'].includes((method ?? 'GET').toUpperCase());
}

function requestIdempotencyKey(): string {
  const suffix = typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function'
    ? crypto.randomUUID()
    : `${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
  return `open-card:${suffix}`;
}

export function readCookie(name: string): string | undefined {
  if (typeof document === 'undefined') return undefined;
  const entry = document.cookie.split(';').map((item) => item.trim()).find((item) => item.startsWith(`${name}=`));
  if (!entry) return undefined;
  const value = entry.slice(name.length + 1);
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

function withRequestDefaults(init: RequestInit = {}): RequestInit {
  const headers = new Headers(init.headers);
  if (isWriteMethod(init.method)) {
    const csrf = readCookie(CSRF_COOKIE_NAME);
    if (csrf) headers.set(CSRF_HEADER_NAME, csrf);
    if (!headers.has('Idempotency-Key')) headers.set('Idempotency-Key', requestIdempotencyKey());
  }
  return { ...init, credentials: 'same-origin', headers };
}

function asAuthSession(value: unknown, mode: AuthSession['mode']): AuthSession {
  const candidate = isRecord(value) && isRecord(value.session) ? value.session : value;
  if (!isRecord(candidate) || typeof candidate.authenticated !== 'boolean') {
    throw new Error('Authentication response did not match the session contract');
  }
  if (!candidate.authenticated) return { authenticated: false, mode };
  return {
    authenticated: true,
    mode,
    username: typeof candidate.username === 'string' ? candidate.username : undefined,
    expiresAt: typeof candidate.expires_at === 'string' ? candidate.expires_at : undefined,
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

function safeErrorBody(value: unknown): { code: string; message: string } | undefined {
  if (!isRecord(value) || typeof value.code !== 'string' || typeof value.message !== 'string') return undefined;
  return { code: value.code, message: value.message };
}

function optionalString(value: unknown): string | null | undefined {
  return value === null ? null : typeof value === 'string' ? value : undefined;
}

function requireString(value: unknown, field: string): string {
  if (typeof value !== 'string' || value.length === 0) throw new Error(`${field} is required`);
  return value;
}

function asFailureState(value: unknown): FailureState | null {
  if (value === null || value === undefined) return null;
  if (!isRecord(value)) throw new Error('Failure state is invalid');
  return {
    code: requireString(value.code, 'failure.code'),
    message: requireString(value.message, 'failure.message'),
    retryable: typeof value.retryable === 'boolean' ? value.retryable : undefined,
  };
}

function asDomainVerification(value: unknown): DomainVerification {
  if (!isRecord(value)) throw new Error('Domain verification is invalid');
  const method = value.method;
  if (method !== 'dns_txt' && method !== 'cname' && method !== 'public_dns_read_only') throw new Error('Domain verification method is invalid');
  const status = value.status;
  if (status !== 'unconfigured' && status !== 'pending' && status !== 'verifying' && status !== 'certificate_pending' && status !== 'ready' && status !== 'failed') throw new Error('Domain verification status is invalid');
  return {
    method,
    status,
    name: optionalString(value.name),
    value: optionalString(value.value),
    observedAt: optionalString(value.observed_at),
  };
}

function asCertificateStatus(value: unknown): CertificateStatus {
  if (!isRecord(value)) throw new Error('Certificate status is invalid');
  const status = value.status;
  if (status !== 'pending' && status !== 'issuing' && status !== 'ready' && status !== 'failed') throw new Error('Certificate status is invalid');
  return {
    status,
    subject: optionalString(value.subject),
    notAfter: optionalString(value.not_after),
  };
}

function asApplicationDomain(value: unknown): ApplicationDomain {
  if (!isRecord(value)) throw new Error('Application domain is invalid');
  const kind = value.kind;
  if (kind !== 'platform' && kind !== 'custom') throw new Error('Application domain kind is invalid');
  const status = value.status;
  if (status !== 'unconfigured' && status !== 'pending' && status !== 'verifying' && status !== 'certificate_pending' && status !== 'ready' && status !== 'failed') throw new Error('Application domain status is invalid');
  if (!Object.prototype.hasOwnProperty.call(value, 'convergence')) throw new Error('Application domain convergence is missing');
  const convergence = value.convergence;
  let parsedConvergence: ApplicationDomain['convergence'] = null;
  if (convergence !== null && convergence !== undefined) {
    if (!isRecord(convergence) || !['converge', 'unbind'].includes(String(convergence.kind))) throw new Error('Application domain convergence is invalid');
    const phase = convergence.phase;
    const status = convergence.status;
    if (!['queued', 'route_prepared', 'internal_route_active', 'tls_allowed', 'certificate_observed', 'serving', 'unbind_route_removed', 'completed', 'failed', 'recovery_required'].includes(String(phase)) || !['queued', 'leased', 'completed', 'failed', 'recovery_required'].includes(String(status))) throw new Error('Application domain convergence is invalid');
    const lastError = optionalString(convergence.last_error);
    if (typeof lastError === 'string' && !/^[a-z0-9_:-]{1,120}$/.test(lastError)) throw new Error('Application domain convergence error is invalid');
    parsedConvergence = { id: requireString(convergence.id, 'Application domain convergence id'), kind: convergence.kind as NonNullable<ApplicationDomain['convergence']>['kind'], phase: phase as NonNullable<ApplicationDomain['convergence']>['phase'], status: status as NonNullable<ApplicationDomain['convergence']>['status'], lastError: lastError ?? undefined };
  }
  return {
    id: requireString(value.id, 'domain.id'),
    hostname: requireString(value.hostname, 'domain.hostname'),
    kind,
    status,
    cnameTarget: optionalString(value.cname_target) ?? null,
    verification: asDomainVerification(value.verification),
    certificate: asCertificateStatus(value.certificate),
    failure: asFailureState(value.failure),
    serving: value.serving === true,
    convergence: parsedConvergence,
  };
}

function asPlatformDomainSettings(value: unknown): PlatformDomainSettingsResponse {
  if (!isRecord(value)) throw new Error('Platform domain settings are invalid');
  const status = value.status;
  if (status !== 'unconfigured' && status !== 'pending' && status !== 'verifying' && status !== 'certificate_pending' && status !== 'ready' && status !== 'failed') throw new Error('Platform domain status is invalid');
  const nextAction = value.next_action;
  if (nextAction !== 'configure_base_domain' && nextAction !== 'publish_verification_record' && nextAction !== 'wait_for_verification' && nextAction !== 'wait_for_certificate' && nextAction !== 'ready' && nextAction !== 'retry') throw new Error('Platform domain next action is invalid');
  if (!Array.isArray(value.dns_records)) throw new Error('Platform DNS records are invalid');
  const dnsRecords = value.dns_records.map((record) => {
    if (!isRecord(record) || record.type !== 'A') throw new Error('Platform DNS record is invalid');
    const purpose = record.purpose;
    if (purpose !== 'console' && purpose !== 'ingress' && purpose !== 'platform_app_wildcard') throw new Error('Platform DNS record purpose is invalid');
    return { hostname: requireString(record.hostname, 'dns_record.hostname'), type: 'A' as const, value: requireString(record.value, 'dns_record.value'), purpose: purpose as 'console' | 'ingress' | 'platform_app_wildcard' };
  });
  return {
    status,
    baseDomain: optionalString(value.base_domain) ?? null,
    consoleDomain: optionalString(value.console_domain) ?? null,
    wildcardPattern: optionalString(value.wildcard_pattern) ?? null,
    dnsRecords,
    verification: asDomainVerification(value.verification),
    certificate: asCertificateStatus(value.certificate),
    failure: asFailureState(value.failure),
    nextAction,
  };
}

function asApplicationDomains(value: unknown): ApplicationDomainsResponse {
  if (!isRecord(value) || !Array.isArray(value.items)) throw new Error('Application domains response is invalid');
  return { items: value.items.map(asApplicationDomain) };
}

function asApplicationDomainResponse(value: unknown): ApplicationDomainResponse {
  if (!isRecord(value)) throw new Error('Application domain response is invalid');
  return { domain: asApplicationDomain(value.domain) };
}

function asApplicationDomainUnbindResponse(value: unknown): ApplicationDomainUnbindResponse {
  if (!isRecord(value) || !isRecord(value.operation) || !['queued', 'in_progress', 'completed', 'failed'].includes(String(value.operation.status))) {
    throw new Error('Application domain unbind response is invalid');
  }
  return {
    operation: {
      id: requireString(value.operation.id, 'unbind.operation.id'),
      status: value.operation.status as ApplicationDomainUnbindOperation['status'],
      domainId: requireString(value.operation.domain_id, 'unbind.operation.domain_id'),
    },
  };
}

function asAccessRouteStatus(value: unknown): AccessRouteStatus {
  if (!isRecord(value)) throw new Error('Access route status is invalid');
  return {
    desired: value.desired === true,
    serving: value.serving === true,
    routeId: optionalString(value.route_id),
  };
}

function asApplicationAccess(value: unknown): ApplicationAccessResponse {
  if (!isRecord(value) || !Array.isArray(value.customDomains)) throw new Error('Application access response is invalid');
  return {
    runtimeReady: value.runtimeReady === true,
    ipFallback: optionalString(value.ipFallback) ?? null,
    platformAddress: value.platformAddress === null || value.platformAddress === undefined ? null : asApplicationDomain(value.platformAddress),
    customDomains: value.customDomains.map(asApplicationDomain),
    route: asAccessRouteStatus(value.route),
    certificate: asCertificateStatus(value.certificate),
    serving: value.serving === true,
  };
}

function asApplicationPublishResponse(value: unknown): ApplicationPublishResponse {
  if (!isRecord(value) || value.status !== 'deploying') throw new Error('Application publish response is invalid');
  return {
    status: 'deploying',
    operationId: requireString(value.operation_id, 'publish.operation_id'),
    releaseId: requireString(value.release_id, 'publish.release_id'),
    deploymentId: requireString(value.deployment_id, 'publish.deployment_id'),
    taskId: requireString(value.task_id, 'publish.task_id'),
    sourceRevisionId: requireString(value.source_revision_id, 'publish.source_revision_id'),
  };
}

function asApplicationDetail(value: unknown): ApplicationDetail {
  if (!isRecord(value)) throw new Error('Application detail is invalid');
  return {
    id: requireString(value.id, 'application.id'),
    name: requireString(value.name, 'application.name'),
    createdAt: requireString(value.created_at, 'application.created_at'),
    updatedAt: requireString(value.updated_at, 'application.updated_at'),
    sourceUploadId: optionalString(value.source_upload_id) ?? null,
    access: asApplicationAccess(value.access),
  };
}

function asSourceUpload(value: unknown): SourceUploadResponse {
  if (!isRecord(value)) throw new Error('Source upload response is invalid');
  const kind = value.kind;
  if (kind !== 'archive' && kind !== 'directory') throw new Error('Source upload kind is invalid');
  const status = value.status;
  if (status !== 'ready' && status !== 'claimed' && status !== 'expired' && status !== 'failed') throw new Error('Source upload status is invalid');
  if (typeof value.bytes !== 'number' || !Number.isFinite(value.bytes) || value.bytes < 0) throw new Error('Source upload bytes are invalid');
  if (typeof value.file_count !== 'number' || !Number.isInteger(value.file_count) || value.file_count < 1) throw new Error('Source upload file count is invalid');
  const digest = requireString(value.digest, 'upload.digest');
  if (!/^sha256:[0-9a-f]{64}$/.test(digest)) throw new Error('Source upload digest is invalid');
  return {
    uploadId: requireString(value.id, 'upload.id'),
    kind,
    status,
    digest,
    bytes: value.bytes,
    fileCount: value.file_count,
    expiresAt: requireString(value.expires_at, 'upload.expires_at'),
  };
}

function isBlob(value: unknown): value is Blob {
  return typeof Blob !== 'undefined' && value instanceof Blob;
}

function isFormData(value: unknown): value is FormData {
  return typeof FormData !== 'undefined' && value instanceof FormData;
}

function invalidUpload(message: string): ApiRequestError {
  return new ApiRequestError(422, message, 'validation', 'invalid_upload');
}

function fileName(value: Blob): string | undefined {
  return 'name' in value && typeof value.name === 'string' ? value.name : undefined;
}

function fileRelativePath(file: File): string {
  const relativePath = (file as File & { webkitRelativePath?: string }).webkitRelativePath;
  return relativePath || file.name;
}

export function normalizeUploadPath(path: string): string {
  if (
    !path
    || path.includes('\\')
    || path.includes('\u0000')
    || path.startsWith('/')
    || path.startsWith('\\\\')
    || /^[A-Za-z]:/.test(path)
    || path.includes('//')
    || path.endsWith('/')
    || path.split('/').some((segment) => segment.length === 0 || segment === '.' || segment === '..')
    || !/^[A-Za-z0-9][A-Za-z0-9._/@+ -]*$/.test(path)
  ) {
    throw invalidUpload('上传目录包含不安全的相对路径。');
  }
  return path;
}

function validateManifest(manifest: SourceUploadManifest, files: Blob[], paths: string[]): SourceUploadManifest {
  if (!isRecord(manifest) || !Array.isArray(manifest.files) || manifest.files.length === 0 || manifest.files.length !== files.length) {
    throw invalidUpload('上传目录 manifest 与文件数量不一致。');
  }
  const entries = new Map<string, SourceUploadManifestEntry>();
  for (const rawEntry of manifest.files) {
    if (!isRecord(rawEntry) || typeof rawEntry.path !== 'string') throw invalidUpload('上传目录 manifest 条目无效。');
    const path = normalizeUploadPath(rawEntry.path);
    if (entries.has(path) || typeof rawEntry.bytes !== 'number' || !Number.isInteger(rawEntry.bytes) || rawEntry.bytes < 0 || rawEntry.bytes !== files[paths.indexOf(path)]?.size) {
      throw invalidUpload('上传目录 manifest 与文件内容不一致。');
    }
    if (rawEntry.digest !== undefined && (typeof rawEntry.digest !== 'string' || !/^sha256:[0-9a-f]{64}$/.test(rawEntry.digest))) {
      throw invalidUpload('上传目录 manifest digest 无效。');
    }
    entries.set(path, { path, bytes: rawEntry.bytes, digest: rawEntry.digest });
  }
  if (paths.some((path) => !entries.has(path))) throw invalidUpload('上传目录 manifest 缺少文件。');
  return { files: [...entries.values()] };
}

async function sourceUploadForm(input: SourceUploadInput): Promise<FormData> {
  if (isFormData(input)) {
    const mode = input.get('mode');
    if (mode === 'archive') {
      const archives = input.getAll('archive');
      if (archives.length !== 1 || !isBlob(archives[0]) || input.getAll('files').length > 0 || input.get('manifest') !== null) {
        throw invalidUpload('archive 与 directory 上传字段不可混用。');
      }
      const form = new FormData();
      form.append('mode', 'archive');
      form.append('archive', archives[0], fileName(archives[0]) ?? 'archive');
      return form;
    }
    if (mode === 'directory') {
      const values = input.getAll('files');
      if (values.length === 0 || values.some((value) => !isBlob(value))) throw invalidUpload('directory 上传必须包含文件。');
      const manifestValue = input.get('manifest');
      if (manifestValue === null) throw invalidUpload('directory 上传必须包含 manifest。');
      const manifestText = typeof manifestValue === 'string' ? manifestValue : isBlob(manifestValue) ? await manifestValue.text() : undefined;
      if (!manifestText) throw invalidUpload('directory manifest 无效。');
      let manifest: SourceUploadManifest;
      try {
        manifest = JSON.parse(manifestText) as SourceUploadManifest;
      } catch {
        throw invalidUpload('directory manifest 无效。');
      }
      const blobs = values as Blob[];
      const paths = blobs.map((value) => normalizeUploadPath(fileName(value) ?? ''));
      const normalizedManifest = validateManifest(manifest, blobs, paths);
      const form = new FormData();
      form.append('mode', 'directory');
      blobs.forEach((file, index) => form.append('files', file, paths[index]));
      form.append('manifest', new Blob([JSON.stringify(normalizedManifest)], { type: 'application/json' }));
      return form;
    }
    throw invalidUpload('上传 mode 必须是 archive 或 directory。');
  }

  const form = new FormData();
  if (input.mode === 'archive') {
    if (!isBlob(input.archive)) throw invalidUpload('archive 必须是 File 或 Blob。');
    form.append('mode', 'archive');
    form.append('archive', input.archive, fileName(input.archive) ?? 'archive');
    return form;
  }

  if (input.mode === 'directory') {
    if (!Array.isArray(input.files) || input.files.length === 0 || input.files.some((file) => !isBlob(file))) throw invalidUpload('directory 上传必须包含文件。');
    const paths = input.files.map(fileRelativePath).map(normalizeUploadPath);
    const normalizedManifest = validateManifest(input.manifest, input.files, paths);
    form.append('mode', 'directory');
    input.files.forEach((file, index) => form.append('files', file, paths[index]));
    form.append('manifest', new Blob([JSON.stringify(normalizedManifest)], { type: 'application/json' }));
    return form;
  }

  throw invalidUpload('上传 mode 必须是 archive 或 directory。');
}

function normalizeApplication(value: unknown): ApplicationSummary {
  if (!isRecord(value) || typeof value.id !== 'string' || typeof value.name !== 'string') {
    throw new Error('OpenAPI response contained an invalid application');
  }
  const source = isRecord(value.source) && (value.source.kind === 'git' || value.source.kind === 'folder' || value.source.kind === 'archive' || value.source.kind === 'unknown')
    ? {
      kind: value.source.kind as ApplicationSource['kind'],
      uploadId: typeof value.source.source_upload_id === 'string' ? value.source.source_upload_id : undefined,
      locator: typeof value.source.locator === 'string' ? value.source.locator : undefined,
      ref: typeof value.source.ref === 'string' ? value.source.ref : undefined,
    }
    : { kind: 'unknown' as const };
  const updatedAt = typeof value.updated_at === 'string' ? value.updated_at : new Date().toISOString();
  const publishing = isRecord(value.publishing) && isPublishingStatus(value.publishing.status)
    ? {
      status: value.publishing.status,
      sequence: typeof value.publishing.sequence === 'number' ? value.publishing.sequence : 0,
      lastEventId: typeof value.publishing.last_event_id === 'string' ? value.publishing.last_event_id : undefined,
      message: typeof value.publishing.message === 'string' ? value.publishing.message : undefined,
      evidenceIds: Array.isArray(value.publishing.evidence_ids) ? value.publishing.evidence_ids.filter((id): id is string => typeof id === 'string') : [],
    }
    : undefined;
  const runtimeStatus = value.runtime_status === 'running' || value.runtime_status === 'attention' || value.runtime_status === 'partial' || value.runtime_status === 'stopped'
    ? value.runtime_status
    : 'unknown';
  const accessValue = isRecord(value.access_state) ? value.access_state : undefined;
  const access = accessValue ? {
    application: accessValue.application === 'running' || accessValue.application === 'not_running' ? accessValue.application : 'unknown',
    ipFallback: accessValue.ip_fallback === 'available' || accessValue.ip_fallback === 'not_ready' ? accessValue.ip_fallback : 'unknown',
    domainVerification: accessValue.domain_verification === 'verifying' || accessValue.domain_verification === 'verified' || accessValue.domain_verification === 'failed' ? accessValue.domain_verification : 'not_configured',
    https: accessValue.https === 'provisioning' || accessValue.https === 'ready' || accessValue.https === 'failed' ? accessValue.https : 'not_requested',
    trafficSwitch: accessValue.traffic_switch === 'switching' || accessValue.traffic_switch === 'serving_current' || accessValue.traffic_switch === 'failed_old_version_serving' ? accessValue.traffic_switch : 'not_switching',
  } satisfies DomainAccessSnapshot : undefined;
  return {
    id: value.id,
    name: value.name,
    slug: typeof value.slug === 'string' ? value.slug : value.id,
    source,
    runtimeStatus,
    runtimeReady: value.runtime_ready === true,
    serving: value.serving === true,
    route: typeof value.route === 'string' ? value.route : undefined,
    access,
    publishing,
    operationId: typeof value.operation_id === 'string' ? value.operation_id : undefined,
    updatedAt,
  };
}

function asApplicationList(value: unknown): ApplicationListResponse {
  if (Array.isArray(value)) return { items: value.map(normalizeApplication) };
  if (isRecord(value) && Array.isArray(value.items)) {
    return {
      items: value.items.map(normalizeApplication),
      nextCursor: typeof value.next_cursor === 'string' ? value.next_cursor : undefined,
    };
  }
  throw new Error('OpenAPI response did not contain an application list');
}

function asCreateApplicationResponse(value: unknown): CreateApplicationResponse {
  if (!isRecord(value)) {
    throw new Error('OpenAPI response did not contain an application');
  }
  const application = normalizeApplication(isRecord(value.application) ? value.application : value);
  return {
    application,
    // The M0 control-plane schema returns the created Application directly;
    // later operation-aware responses can provide operation_id without
    // changing the UI contract.
    operationId: typeof value.operation_id === 'string' ? value.operation_id : `application:${application.id}`,
    environmentId: typeof value.environment_id === 'string' ? value.environment_id : undefined,
    sourceRevisionId: typeof value.source_revision_id === 'string' ? value.source_revision_id : undefined,
  };
}

function createApplicationSourcePayload(source: CreateApplicationSource): Record<string, string> {
  if (source.kind === 'upload') return { kind: 'upload', upload_id: source.uploadId };
  return { kind: 'git', repository_url: source.repositoryUrl, ref: source.ref };
}

function asPublishEvent(value: unknown): PublishEvent {
  if (!isRecord(value)) throw new Error('Invalid publish event payload');
  const id = typeof value.id === 'string' ? value.id : undefined;
  const operationId = typeof value.operation_id === 'string' ? value.operation_id : typeof value.operationId === 'string' ? value.operationId : undefined;
  const applicationId = typeof value.application_id === 'string' ? value.application_id : typeof value.applicationId === 'string' ? value.applicationId : undefined;
  const occurredAt = typeof value.occurred_at === 'string' ? value.occurred_at : typeof value.occurredAt === 'string' ? value.occurredAt : undefined;
  if (
    !id || !operationId || !applicationId || !occurredAt
    || typeof value.sequence !== 'number'
    || !isPublishEventKind(value.kind)
    || !isPublishingStatus(value.status)
  ) {
    throw new Error('Publish event is missing required fields');
  }
  return {
    id,
    operationId,
    applicationId,
    sequence: value.sequence,
    occurredAt,
    kind: value.kind,
    status: value.status,
    message: typeof value.message === 'string' ? value.message : undefined,
    evidenceIds: Array.isArray(value.evidence_ids)
      ? value.evidence_ids.filter((eventId): eventId is string => typeof eventId === 'string')
      : Array.isArray(value.evidenceIds) ? value.evidenceIds.filter((eventId): eventId is string => typeof eventId === 'string') : undefined,
  };
}

function isOperationAction(value: unknown): value is OperationAction {
  return value === 'restart' || value === 'redeploy' || value === 'rollback';
}

function isOperationActionStatus(value: unknown): value is OperationActionStatus {
  return value === 'idle' || value === 'pending' || value === 'running' || value === 'succeeded' || value === 'failed' || value === 'blocked';
}

function isServiceHealth(value: unknown): value is ServiceHealth {
  return value === 'healthy' || value === 'degraded' || value === 'unhealthy' || value === 'unknown';
}

function finiteNonNegative(value: unknown): value is number {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0;
}

function asServiceOperationsFact(value: unknown): ServiceOperationsFact {
  if (!isRecord(value) || typeof value.id !== 'string' || typeof value.name !== 'string' || !isServiceHealth(value.health) || typeof value.required !== 'boolean' || !isRecord(value.resources)) {
    throw new Error('Operations fact contained an invalid service');
  }
  const resources = value.resources;
  if (!finiteNonNegative(resources.cpu_millicores) || !finiteNonNegative(resources.memory_bytes) || !finiteNonNegative(resources.disk_bytes) || !finiteNonNegative(resources.network_rx_bytes) || !finiteNonNegative(resources.network_tx_bytes) || !finiteNonNegative(resources.restart_count)) {
    throw new Error('Operations fact contained invalid actual resources');
  }
  return {
    id: value.id,
    name: value.name,
    health: value.health,
    required: value.required,
    releaseId: typeof value.release_id === 'string' ? value.release_id : undefined,
    exitReason: typeof value.exit_reason === 'string' ? value.exit_reason : undefined,
    resources: {
      cpuMillicores: resources.cpu_millicores,
      memoryBytes: resources.memory_bytes,
      diskBytes: resources.disk_bytes,
      networkRxBytes: resources.network_rx_bytes,
      networkTxBytes: resources.network_tx_bytes,
      restartCount: resources.restart_count,
    },
  };
}

function asOperationActionFact(value: unknown): OperationActionFact {
  if (!isRecord(value) || !isOperationAction(value.action) || !isOperationActionStatus(value.status) || typeof value.enabled !== 'boolean') {
    throw new Error('Operations fact contained an invalid action');
  }
  return {
    action: value.action,
    status: value.status,
    operationId: typeof value.operation_id === 'string' ? value.operation_id : undefined,
    targetServiceId: typeof value.target_service_id === 'string' ? value.target_service_id : undefined,
    message: typeof value.message === 'string' ? value.message : undefined,
    enabled: value.enabled,
  };
}

function asApplicationOperationsFact(value: unknown): ApplicationOperationsFact {
  if (!isRecord(value) || typeof value.version !== 'string' || typeof value.observed_at !== 'string' || typeof value.application_id !== 'string' || typeof value.application_name !== 'string' || typeof value.serving !== 'boolean' || typeof value.impact !== 'string' || typeof value.next_step !== 'string' || value.data_rollback_supported !== false || !Array.isArray(value.services) || !Array.isArray(value.actions)) {
    throw new Error('Operations fact response did not match the M4 contract');
  }
  return {
    version: value.version,
    observedAt: value.observed_at,
    applicationId: value.application_id,
    applicationName: value.application_name,
    serving: value.serving,
    impact: value.impact,
    nextStep: value.next_step,
    services: value.services.map(asServiceOperationsFact),
    actions: value.actions.map(asOperationActionFact),
    dataRollbackSupported: false,
  };
}

function operationsUnavailable(): ApplicationOperationsResult {
  return { status: 'unavailable', message: '运行与运维事实 API 尚未由控制面组合，无法展示或执行 M4 操作。' };
}

function requestUnavailable(): OperationRequestResult {
  return { status: 'unavailable', message: '运行与运维操作 API 尚未由控制面组合，未发送操作。' };
}

function asUsageMeasurement(value: unknown): UsageMeasurement {
  if (!isRecord(value) || !finiteNonNegative(value.actual) || !finiteNonNegative(value.limit) || typeof value.unit !== 'string' || value.unit.length === 0) {
    throw new Error('Usage fact contained an invalid measurement');
  }
  return { actual: value.actual, limit: value.limit, unit: value.unit };
}

function asUsageAnomaly(value: unknown): UsageAnomaly {
  if (!isRecord(value) || typeof value.id !== 'string' || typeof value.observed_at !== 'string' || (value.severity !== 'info' && value.severity !== 'warning' && value.severity !== 'critical') || typeof value.summary !== 'string') {
    throw new Error('Usage fact contained an invalid anomaly');
  }
  return {
    id: value.id,
    observedAt: value.observed_at,
    severity: value.severity,
    summary: value.summary,
    relatedServiceId: typeof value.related_service_id === 'string' ? value.related_service_id : undefined,
    relatedReleaseId: typeof value.related_release_id === 'string' ? value.related_release_id : undefined,
  };
}

function asUsageTrendPoint(value: unknown): UsageTrendPoint {
  if (!isRecord(value) || typeof value.observed_at !== 'string') throw new Error('Usage trend point is invalid');
  return {
    observedAt: value.observed_at,
    cpu: asUsageMeasurement(value.cpu),
    memory: asUsageMeasurement(value.memory),
    disk: asUsageMeasurement(value.disk),
    network: asUsageMeasurement(value.network),
  };
}

function asUsageResources(value: unknown): UsageResourceMeasurements {
  if (!isRecord(value)) throw new Error('Usage resources are invalid');
  return { cpu: asUsageMeasurement(value.cpu), memory: asUsageMeasurement(value.memory), disk: asUsageMeasurement(value.disk), network: asUsageMeasurement(value.network) };
}

function asUsageService(value: unknown): UsageServiceFact {
  if (!isRecord(value) || typeof value.id !== 'string' || typeof value.name !== 'string' || typeof value.release_id !== 'string' || typeof value.runtime !== 'string' || typeof value.started_at !== 'string' || !Array.isArray(value.trend) || !Array.isArray(value.anomalies)) {
    throw new Error('Usage fact contained an invalid service');
  }
  return {
    id: value.id,
    name: value.name,
    releaseId: value.release_id,
    runtime: value.runtime,
    startedAt: value.started_at,
    actual: asUsageResources(value.actual),
    average: asUsageResources(value.average),
    peak: asUsageResources(value.peak),
    configured: asUsageResources(value.configured),
    trend: value.trend.map(asUsageTrendPoint),
    anomalies: value.anomalies.map(asUsageAnomaly),
  };
}

function asApplicationUsageFact(value: unknown): ApplicationUsageFact {
  if (!isRecord(value) || typeof value.version !== 'string' || typeof value.observed_at !== 'string' || typeof value.application_id !== 'string' || typeof value.application_name !== 'string' || value.ai !== 'disabled' || !Array.isArray(value.services) || !Array.isArray(value.anomalies)) {
    throw new Error('Usage fact response did not match the M5 contract');
  }
  return {
    version: value.version,
    observedAt: value.observed_at,
    applicationId: value.application_id,
    applicationName: value.application_name,
    services: value.services.map(asUsageService),
    anomalies: value.anomalies.map(asUsageAnomaly),
    ai: 'disabled',
  };
}

function usageUnavailable(): ApplicationUsageResult {
  return { status: 'unavailable', message: '用量事实 API 尚未由控制面组合，不能以示例数据代替真实观察。' };
}

function asSystemStatus(value: unknown): SystemStatusFact {
  if (!isRecord(value) || !isRecord(value.node) || !isRecord(value.platform_domain) || !isRecord(value.webhooks) || !isRecord(value.backup) || !isRecord(value.alerts)) throw new Error('System status response is invalid');
  const node = value.node;
  const platformDomain = value.platform_domain;
  const webhooks = value.webhooks;
  const nullableString = (candidate: unknown, field: string): string | null => candidate === null ? null : requireString(candidate, field);
  if (node.single_node !== true || (node.readiness !== 'ready' && node.readiness !== 'not_ready' && node.readiness !== 'unconfigured')) throw new Error('System node status is invalid');
  const platformStatus = platformDomain.status;
  if (platformStatus !== 'unconfigured' && platformStatus !== 'pending' && platformStatus !== 'failed' && platformStatus !== 'ready') throw new Error('System platform domain status is invalid');
  if ((webhooks.status !== 'configured' && webhooks.status !== 'unconfigured') || typeof webhooks.enabled_count !== 'number' || !Number.isInteger(webhooks.enabled_count) || webhooks.enabled_count < 0) throw new Error('System webhook status is invalid');
  if (!isRecord(value.backup) || value.backup.status !== 'not_installed' || value.alerts.status !== 'not_installed') throw new Error('System capability status is invalid');
  return {
    version: requireString(value.version, 'system.version'),
    node: { singleNode: true, instanceId: nullableString(node.instance_id, 'system.node.instance_id'), nodeId: nullableString(node.node_id, 'system.node.node_id'), readiness: node.readiness },
    platformDomain: { status: platformStatus, baseDomain: nullableString(platformDomain.base_domain, 'system.platform_domain.base_domain') },
    webhooks: { status: webhooks.status, enabledCount: webhooks.enabled_count },
    backup: { status: 'not_installed' },
    alerts: { status: 'not_installed' },
  };
}

function operationIdempotencyKey(applicationId: string): string {
  const suffix = typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function'
    ? crypto.randomUUID()
    : `${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
  return `m4-operation:${applicationId}:${suffix}`;
}

export interface RestApiClientOptions {
  baseUrl?: string;
  fetchImpl?: typeof fetch;
  eventSourceFactory?: EventSourceFactory;
  eventsUrl?: (operationId: string, baseUrl: string) => string;
  onUnauthorized?: () => void;
  timeoutMs?: number;
}

function parseSseBlock(block: string): { id?: string; data?: string } {
  let id: string | undefined;
  const data: string[] = [];
  for (const line of block.replaceAll('\r\n', '\n').split('\n')) {
    if (!line || line.startsWith(':')) continue;
    const separator = line.indexOf(':');
    const field = separator === -1 ? line : line.slice(0, separator);
    const value = separator === -1 ? '' : line.slice(separator + 1).replace(/^ /, '');
    if (field === 'id') id = value;
    if (field === 'data') data.push(value);
  }
  return { id, data: data.length > 0 ? data.join('\n') : undefined };
}

export class RestApiClient implements ApiClient {
  readonly authMode = 'live' as const;
  private readonly baseUrl: string;
  private readonly fetchImpl: typeof fetch;
  private readonly eventSourceFactory?: EventSourceFactory;
  private readonly eventsUrl: (operationId: string, baseUrl: string) => string;
  private readonly onUnauthorized?: () => void;
  private readonly timeoutMs: number;

  constructor(options: RestApiClientOptions = {}) {
    this.baseUrl = (options.baseUrl ?? API_BASE_URL).replace(/\/$/, '');
    this.fetchImpl = options.fetchImpl ?? fetch.bind(globalThis);
    this.eventSourceFactory = options.eventSourceFactory;
    this.eventsUrl = options.eventsUrl ?? ((operationId, baseUrl) => `${baseUrl}/operations/${encodeURIComponent(operationId)}/events`);
    this.onUnauthorized = options.onUnauthorized;
    this.timeoutMs = Number.isFinite(options.timeoutMs) && (options.timeoutMs ?? 0) > 0 ? options.timeoutMs as number : DEFAULT_TIMEOUT_MS;
  }

  private async request(path: string, init: RequestInit = {}, notifyUnauthorized = true, timeoutMs = this.timeoutMs): Promise<Response> {
    const requestInit = withRequestDefaults(init);
    const controller = new AbortController();
    let timedOut = false;
    let timeout: ReturnType<typeof setTimeout> | undefined;
    const forwardAbort = () => controller.abort(init.signal?.reason);
    if (init.signal) {
      if (init.signal.aborted) forwardAbort();
      else init.signal.addEventListener('abort', forwardAbort, { once: true });
    }
    if (timeoutMs > 0) {
      timeout = setTimeout(() => {
        timedOut = true;
        controller.abort();
      }, timeoutMs);
    }
    try {
      const response = await this.fetchImpl(`${this.baseUrl}${path}`, { ...requestInit, signal: controller.signal });
      if (response.status === 401 && notifyUnauthorized) this.onUnauthorized?.();
      return response;
    } catch (error) {
      if (timedOut) throw createTimeoutError();
      if (init.signal?.aborted) throw error;
      throw createNetworkError();
    } finally {
      if (timeout) clearTimeout(timeout);
      init.signal?.removeEventListener('abort', forwardAbort);
    }
  }

  private async json(response: Response, fallbackMessage: string): Promise<unknown> {
    let body: unknown;
    try {
      body = await response.json();
    } catch {
      body = undefined;
    }
    if (!response.ok) throw createResponseError(response.status, fallbackMessage, safeErrorBody(body));
    return body;
  }

  private async noContent(response: Response, fallbackMessage: string): Promise<void> {
    if (!response.ok) {
      let body: unknown;
      try {
        body = safeErrorBody(await response.json());
      } catch {
        body = undefined;
      }
      throw createResponseError(response.status, fallbackMessage, body);
    }
  }

  async getSession(signal?: AbortSignal): Promise<AuthSession> {
    const response = await this.request('/auth/session', { signal });
    if (response.status === 401) return { authenticated: false, mode: this.authMode };
    return asAuthSession(await this.json(response, 'Unable to load administrator session'), this.authMode);
  }

  async login(input: AuthLoginInput, signal?: AbortSignal): Promise<AuthSession> {
    const response = await this.request('/auth/login', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ password: input.password }),
      signal,
    });
    return asAuthSession(await this.json(response, 'Administrator login was not accepted'), this.authMode);
  }

  async logout(signal?: AbortSignal): Promise<void> {
    const response = await this.request('/auth/logout', { method: 'POST', signal });
    if (response.status === 401) return;
    await this.noContent(response, 'Logout was not completed');
  }

  async changePassword(input: PasswordChangeInput, signal?: AbortSignal): Promise<AuthSession> {
    const response = await this.request('/auth/password', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ current_password: input.currentPassword, new_password: input.newPassword }),
      signal,
    });
    if (response.status === 204) return { authenticated: false, mode: this.authMode };
    return asAuthSession(await this.json(response, 'Password rotation was not completed'), this.authMode);
  }

  async listApplications(signal?: AbortSignal): Promise<ApplicationListResponse> {
    const response = await this.request('/applications', { signal });
    return asApplicationList(await this.json(response, 'Unable to list applications'));
  }

  async createApplication(input: CreateApplicationInput, signal?: AbortSignal): Promise<CreateApplicationResponse> {
    const response = await this.request('/applications', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ name: input.name, source: createApplicationSourcePayload(input.source) }),
      signal,
    });
    return asCreateApplicationResponse(await this.json(response, 'Unable to create application'));
  }

  async getApplication(applicationId: string, signal?: AbortSignal): Promise<ApplicationDetail> {
    const response = await this.request(`/applications/${encodeURIComponent(applicationId)}`, { signal });
    return asApplicationDetail(await this.json(response, 'Unable to load application detail'));
  }

  async getPlatformDomainSettings(signal?: AbortSignal): Promise<PlatformDomainSettingsResponse> {
    const response = await this.request('/settings/platform-domain', { signal });
    return asPlatformDomainSettings(await this.json(response, 'Unable to load platform domain settings'));
  }

  async putPlatformDomainSettings(input: PlatformDomainSettingsRequest, signal?: AbortSignal): Promise<PlatformDomainSettingsResponse> {
    const response = await this.request('/settings/platform-domain', {
      method: 'PUT',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ base_domain: input.baseDomain }),
      signal,
    });
    return asPlatformDomainSettings(await this.json(response, 'Unable to update platform domain settings'));
  }

  async listApplicationDomains(applicationId: string, signal?: AbortSignal): Promise<ApplicationDomainsResponse> {
    const response = await this.request(`/applications/${encodeURIComponent(applicationId)}/domains`, { signal });
    return asApplicationDomains(await this.json(response, 'Unable to list application domains'));
  }

  async bindApplicationCustomDomain(applicationId: string, input: CustomDomainBindRequest, signal?: AbortSignal): Promise<ApplicationDomainResponse> {
    const response = await this.request(`/applications/${encodeURIComponent(applicationId)}/domains`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ hostname: input.hostname }),
      signal,
    });
    return asApplicationDomainResponse(await this.json(response, 'Unable to bind application domain'));
  }

  async verifyApplicationDomain(applicationId: string, domainId: string, signal?: AbortSignal): Promise<ApplicationDomainResponse> {
    const response = await this.request(`/applications/${encodeURIComponent(applicationId)}/domains/${encodeURIComponent(domainId)}/verify`, {
      method: 'POST',
      signal,
    });
    return asApplicationDomainResponse(await this.json(response, 'Unable to verify application domain'));
  }

  async unbindApplicationDomain(applicationId: string, domainId: string, idempotencyKey: string, signal?: AbortSignal): Promise<ApplicationDomainUnbindResponse> {
	const response = await this.request(`/applications/${encodeURIComponent(applicationId)}/domains/${encodeURIComponent(domainId)}`, {
		method: 'DELETE',
		headers: { 'idempotency-key': idempotencyKey },
		signal,
    });
    const value = asApplicationDomainUnbindResponse(await this.json(response, 'Unable to request application domain unbind'));
    if (value.operation.domainId !== domainId) throw new Error('Application domain unbind response addressed a different domain');
    return value;
  }

  async getApplicationAccess(applicationId: string, signal?: AbortSignal): Promise<ApplicationAccessResponse> {
    const response = await this.request(`/applications/${encodeURIComponent(applicationId)}/access`, { signal });
    return asApplicationAccess(await this.json(response, 'Unable to load application access'));
  }

  async publishApplication(applicationId: string, input: ApplicationPublishInput, signal?: AbortSignal): Promise<ApplicationPublishResponse> {
    const response = await this.request(`/applications/${encodeURIComponent(applicationId)}/publishes`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        build_kind: input.buildKind,
        context_path: input.contextPath,
        ...(input.dockerfilePath ? { dockerfile_path: input.dockerfilePath } : {}),
        service_name: input.serviceName,
        container_port: input.containerPort,
      }),
      signal,
    }, true, 10 * 60 * 1000);
    return asApplicationPublishResponse(await this.json(response, 'Unable to publish application'));
  }

  async createSourceUpload(input: SourceUploadInput, signal?: AbortSignal): Promise<SourceUploadResponse> {
    const form = await sourceUploadForm(input);
    const response = await this.request('/source-uploads', { method: 'POST', body: form, signal });
    return asSourceUpload(await this.json(response, 'Unable to upload source'));
  }

  async getSourceUpload(uploadId: string, signal?: AbortSignal): Promise<SourceUploadResponse> {
    const response = await this.request(`/source-uploads/${encodeURIComponent(uploadId)}`, { signal });
    return asSourceUpload(await this.json(response, 'Unable to load source upload'));
  }

  private subscribeWithEventSource(operationId: string, listener: PublishEventListener, onStateChange?: (state: PublishConnectionState) => void): () => void {
    const seenIds = new Set<string>();
    let lastEventId: string | undefined;
    let retryIndex = 0;
    let source: EventSourceLike | undefined;
    let sourceCleanup: (() => void) | undefined;
    let retryTimer: ReturnType<typeof setTimeout> | undefined;
    let closed = false;

    const scheduleReconnect = () => {
      if (closed || retryTimer) return;
      const delay = SSE_RETRY_DELAYS_MS[Math.min(retryIndex, SSE_RETRY_DELAYS_MS.length - 1)];
      retryIndex = Math.min(retryIndex + 1, SSE_RETRY_DELAYS_MS.length - 1);
      retryTimer = setTimeout(() => {
        retryTimer = undefined;
        connect();
      }, delay);
    };

    const closeSource = () => {
      if (!source) return;
      sourceCleanup?.();
      sourceCleanup = undefined;
      source.onerror = null;
      source.onopen = null;
      source.close();
      source = undefined;
    };

    const connect = () => {
      if (closed || source) return;
      onStateChange?.('connecting');
      const currentSource = this.eventSourceFactory?.(this.eventsUrl(operationId, this.baseUrl), {
        withCredentials: true,
        ...(lastEventId ? { lastEventId } : {}),
      });
      if (!currentSource) {
        onStateChange?.('offline');
        return;
      }
      source = currentSource;
      const onMessage: EventListener = (raw) => {
        try {
          const event = asPublishEvent(JSON.parse((raw as MessageEvent<string>).data) as unknown);
          if (seenIds.has(event.id)) return;
          seenIds.add(event.id);
          lastEventId = event.id;
          listener(event);
        } catch {
          // Ignore malformed events; the next valid event remains authoritative.
        }
      };
      const onOpen = () => { retryIndex = 0; onStateChange?.('connected'); };
      const onError = (event: Event) => {
        if (closed) return;
        const status = (event as Event & { status?: unknown }).status;
        closeSource();
        if (status === 401) {
          closed = true;
          onStateChange?.('auth_required');
          this.onUnauthorized?.();
          return;
        }
        onStateChange?.('offline');
        onStateChange?.('retrying');
        scheduleReconnect();
      };
      currentSource.addEventListener('message', onMessage);
      currentSource.onopen = onOpen;
      currentSource.onerror = onError;
      sourceCleanup = () => currentSource.removeEventListener('message', onMessage);
    };

    connect();
    return () => {
      closed = true;
      if (retryTimer) clearTimeout(retryTimer);
      retryTimer = undefined;
      closeSource();
      onStateChange?.('closed');
    };
  }

  private subscribeWithFetch(operationId: string, listener: PublishEventListener, onStateChange?: (state: PublishConnectionState) => void): () => void {
    const seenIds = new Set<string>();
    let lastEventId: string | undefined;
    let retryIndex = 0;
    let retryTimer: ReturnType<typeof setTimeout> | undefined;
    let controller: AbortController | undefined;
    let closed = false;

    const scheduleReconnect = () => {
      if (closed || retryTimer) return;
      const delay = SSE_RETRY_DELAYS_MS[Math.min(retryIndex, SSE_RETRY_DELAYS_MS.length - 1)];
      retryIndex = Math.min(retryIndex + 1, SSE_RETRY_DELAYS_MS.length - 1);
      retryTimer = setTimeout(() => {
        retryTimer = undefined;
        connect();
      }, delay);
    };

    const readStream = async () => {
      controller = new AbortController();
      const response = await this.request(this.eventsUrl(operationId, this.baseUrl).replace(this.baseUrl, ''), {
        headers: {
          Accept: 'text/event-stream',
          ...(lastEventId ? { 'Last-Event-ID': lastEventId } : {}),
        },
        signal: controller.signal,
      }, false, 0);
      if (!response.ok) {
        let body: unknown;
        try {
          body = safeErrorBody(await response.json());
        } catch {
          body = undefined;
        }
        throw createResponseError(response.status, '事件流连接不可用。', body);
      }
      if (!response.body) throw createNetworkError();
      retryIndex = 0;
      onStateChange?.('connected');
      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';
      const emitBlock = (block: string) => {
        const parsed = parseSseBlock(block);
        if (!parsed.data) return;
        try {
          const event = asPublishEvent(JSON.parse(parsed.data) as unknown);
          if (seenIds.has(event.id)) return;
          seenIds.add(event.id);
          lastEventId = event.id;
          listener(event);
        } catch {
          // Ignore malformed events; the next valid event remains authoritative.
        }
      };
      while (!closed) {
        const chunk = await reader.read();
        if (chunk.done) break;
        buffer += decoder.decode(chunk.value, { stream: true });
        const blocks = buffer.replaceAll('\r\n', '\n').split('\n\n');
        buffer = blocks.pop() ?? '';
        blocks.forEach(emitBlock);
      }
      if (buffer) emitBlock(buffer);
      if (!closed) {
        onStateChange?.('retrying');
        scheduleReconnect();
      }
    };

    const connect = () => {
      if (closed) return;
      onStateChange?.('connecting');
      void readStream().catch((error: unknown) => {
        if (closed) return;
        if (error instanceof ApiRequestError && error.kind === 'auth') {
          closed = true;
          onStateChange?.('auth_required');
          this.onUnauthorized?.();
          return;
        }
        onStateChange?.('offline');
        onStateChange?.('retrying');
        scheduleReconnect();
      });
    };

    connect();
    return () => {
      closed = true;
      if (retryTimer) clearTimeout(retryTimer);
      retryTimer = undefined;
      controller?.abort();
      onStateChange?.('closed');
    };
  }

  subscribeToPublishEvents(operationId: string, listener: PublishEventListener, onStateChange?: (state: PublishConnectionState) => void): () => void {
    return this.eventSourceFactory
      ? this.subscribeWithEventSource(operationId, listener, onStateChange)
      : this.subscribeWithFetch(operationId, listener, onStateChange);
  }

  async getApplicationOperations(applicationId: string, signal?: AbortSignal): Promise<ApplicationOperationsResult> {
    const response = await this.request(`/applications/${encodeURIComponent(applicationId)}/operations`, { signal });
    if (response.status === 404 || response.status === 501 || response.status === 503) return operationsUnavailable();
    return { status: 'available', facts: asApplicationOperationsFact(await this.json(response, 'Unable to load operations facts')) };
  }

  async getApplicationUsage(applicationId: string, mode: 'normal' | 'operations', signal?: AbortSignal): Promise<ApplicationUsageResult> {
    const response = await this.request(`/applications/${encodeURIComponent(applicationId)}/usage?mode=${encodeURIComponent(mode)}`, { signal });
    if (response.status === 404 || response.status === 501 || response.status === 503) return usageUnavailable();
    return { status: 'available', facts: asApplicationUsageFact(await this.json(response, 'Unable to load usage facts')) };
  }

  async getSystemStatus(signal?: AbortSignal): Promise<SystemStatusResult> {
    const response = await this.request('/settings/system-status', { signal });
    return { status: 'available', facts: asSystemStatus(await this.json(response, 'Unable to load system status')) };
  }

  async requestApplicationOperation(applicationId: string, request: OperationRequest, signal?: AbortSignal): Promise<OperationRequestResult> {
    const response = await this.request(`/applications/${encodeURIComponent(applicationId)}/operations`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'idempotency-key': operationIdempotencyKey(applicationId),
      },
      body: JSON.stringify({
        action: request.action,
        target_service_id: request.targetServiceId,
        expected_version: request.expectedVersion,
        reason: `operator requested ${request.action} after reviewing facts ${request.expectedVersion}`,
      }),
      signal,
    });
    if (response.status === 404 || response.status === 501 || response.status === 503) return requestUnavailable();
    const body: unknown = await this.json(response, `Unable to request ${request.action}`);
    const operationId = isRecord(body) && typeof body.operation_id === 'string' ? body.operation_id : undefined;
    return { status: 'accepted', operationId, message: '控制面已接受操作请求，正在等待新的事实版本。' };
  }
}

const stubApplications: ApplicationSummary[] = [
  {
    id: 'app-notes',
    name: '团队知识库',
    slug: 'team-notes',
    source: { kind: 'git', locator: 'https://git.example.invalid/team/notes.git', ref: 'main' },
    runtimeStatus: 'running',
    runtimeReady: true,
    serving: true,
    route: '192.168.31.64:31001',
    lastRelease: { id: 'rel-notes-12', version: 'main@8d12f1e', createdAt: '2026-08-24T08:30:00.000Z' },
    publishing: { status: 'succeeded', sequence: 4, lastEventId: 'evt-notes-4', evidenceIds: ['ev-notes-4'] },
    operationId: 'op-notes-12',
    updatedAt: '2026-08-24T08:30:00.000Z',
  },
  {
    id: 'app-portal',
    name: '客户门户',
    slug: 'customer-portal',
    source: { kind: 'archive', locator: 'customer-portal.tgz' },
    runtimeStatus: 'attention',
    runtimeReady: true,
    serving: false,
    route: '192.168.31.64:31002',
    lastRelease: { id: 'rel-portal-04', version: 'upload@2c1b4d0', createdAt: '2026-08-23T19:10:00.000Z' },
    publishing: { status: 'failed', sequence: 4, lastEventId: 'evt-portal-4', message: '入口健康检查失败', evidenceIds: ['ev-portal-4'] },
    operationId: 'op-portal-04',
    updatedAt: '2026-08-23T19:10:00.000Z',
  },
];

function cloneApplication(application: ApplicationSummary): ApplicationSummary {
  return {
    ...application,
    source: { ...application.source },
    lastRelease: application.lastRelease ? { ...application.lastRelease } : undefined,
    publishing: application.publishing ? { ...application.publishing, evidenceIds: [...application.publishing.evidenceIds] } : undefined,
  };
}

function randomId(prefix: string): string {
  return `${prefix}-${Math.random().toString(36).slice(2, 10)}`;
}

/**
 * Deterministic local adapter for the M0 UI shell. It mirrors the same
 * operation/event contract as RestApiClient and is selected explicitly with
 * VITE_API_MODE=stub (the default while the control-plane API is not present).
 */
export class StubApiClient implements ApiClient {
  readonly authMode = 'stub' as const;
  private authenticated = false;
  private applications = stubApplications.map(cloneApplication);
  private listeners = new Map<string, Set<PublishEventListener>>();

  async getSession(): Promise<AuthSession> {
    return this.authenticated ? { authenticated: true, mode: this.authMode, username: 'admin' } : { authenticated: false, mode: this.authMode };
  }

  async login(input: AuthLoginInput): Promise<AuthSession> {
    if (input.username.trim() !== 'admin' || input.password.length === 0) {
      throw new ApiRequestError(401, 'Administrator login was not accepted');
    }
    this.authenticated = true;
    return { authenticated: true, mode: this.authMode, username: 'admin' };
  }

  async logout(): Promise<void> {
    this.authenticated = false;
  }

  async changePassword(input: PasswordChangeInput): Promise<AuthSession> {
    if (!this.authenticated || !input.currentPassword || !input.newPassword) {
      throw new ApiRequestError(401, 'Administrator session is not authenticated');
    }
    this.authenticated = false;
    return { authenticated: false, mode: this.authMode };
  }

  private requireAuthentication(): void {
    if (!this.authenticated) throw new ApiRequestError(401, 'Administrator session is not authenticated');
  }

  async listApplications(): Promise<ApplicationListResponse> {
    this.requireAuthentication();
    return { items: this.applications.map(cloneApplication) };
  }

  async createApplication(input: CreateApplicationInput): Promise<CreateApplicationResponse> {
    this.requireAuthentication();
    const id = randomId('app');
    const operationId = randomId('op');
    const now = new Date().toISOString();
    const application: ApplicationSummary = {
      id,
      name: input.name,
      slug: input.name.toLowerCase().trim().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') || id,
      source: input.source.kind === 'git'
        ? { kind: 'git', locator: input.source.repositoryUrl, ref: input.source.ref }
        : { kind: 'archive', locator: `upload:${input.source.uploadId}` },
      runtimeStatus: 'unknown',
      runtimeReady: false,
      serving: false,
      publishing: createPublishingSnapshot(),
      operationId,
      updatedAt: now,
    };
    this.applications = [application, ...this.applications];

    const timeline: Array<Pick<PublishEvent, 'kind' | 'status' | 'message'>> = [
      { kind: 'operation.created', status: 'preparing', message: '已收到发布请求，正在检查来源' },
      { kind: 'build.started', status: 'building', message: '正在受限构建并固定镜像摘要' },
      { kind: 'deployment.started', status: 'deploying', message: '正在部署到预设单机并进行健康验证' },
      { kind: 'operation.succeeded', status: 'succeeded', message: '发布成功，证据已记录' },
    ];
    timeline.forEach((entry, index) => {
      setTimeout(() => this.emit({
        id: randomId('evt'),
        operationId,
        applicationId: id,
        sequence: index + 1,
        occurredAt: new Date().toISOString(),
        ...entry,
        evidenceIds: index === timeline.length - 1 ? [randomId('evidence')] : undefined,
      }), 80 + index * 520);
    });

    return { application: cloneApplication(application), operationId };
  }

  async getApplication(applicationId: string): Promise<ApplicationDetail> {
    this.requireAuthentication();
    const application = this.applications.find((item) => item.id === applicationId);
    if (!application) throw new ApiRequestError(404, '应用不存在。', 'http', 'not_found');
    return {
      id: application.id,
      name: application.name,
      createdAt: application.lastRelease?.createdAt ?? application.updatedAt,
      updatedAt: application.updatedAt,
      sourceUploadId: null,
      access: {
        runtimeReady: application.runtimeReady,
        ipFallback: application.route ?? null,
        platformAddress: null,
        customDomains: [],
        route: { desired: application.serving, serving: application.serving, routeId: null },
        certificate: { status: 'pending', subject: null, notAfter: null },
        serving: application.serving,
      },
    };
  }

  private domainAndUploadUnavailable(): never {
    throw new ApiRequestError(undefined, '本地演示模式不连接真实域名或上传 API。', 'unavailable', 'stub_unavailable');
  }

  async getPlatformDomainSettings(_signal?: AbortSignal): Promise<PlatformDomainSettingsResponse> {
    this.requireAuthentication();
    return this.domainAndUploadUnavailable();
  }

  async putPlatformDomainSettings(_input: PlatformDomainSettingsRequest, _signal?: AbortSignal): Promise<PlatformDomainSettingsResponse> {
    this.requireAuthentication();
    return this.domainAndUploadUnavailable();
  }

  async listApplicationDomains(_applicationId: string, _signal?: AbortSignal): Promise<ApplicationDomainsResponse> {
    this.requireAuthentication();
    return this.domainAndUploadUnavailable();
  }

  async bindApplicationCustomDomain(_applicationId: string, _input: CustomDomainBindRequest, _signal?: AbortSignal): Promise<ApplicationDomainResponse> {
    this.requireAuthentication();
    return this.domainAndUploadUnavailable();
  }

  async verifyApplicationDomain(_applicationId: string, _domainId: string, _signal?: AbortSignal): Promise<ApplicationDomainResponse> {
    this.requireAuthentication();
    return this.domainAndUploadUnavailable();
  }

  async unbindApplicationDomain(_applicationId: string, _domainId: string, _idempotencyKey: string, _signal?: AbortSignal): Promise<ApplicationDomainUnbindResponse> {
    this.requireAuthentication();
    return this.domainAndUploadUnavailable();
  }

  async getApplicationAccess(_applicationId: string, _signal?: AbortSignal): Promise<ApplicationAccessResponse> {
    this.requireAuthentication();
    return this.domainAndUploadUnavailable();
  }

  async publishApplication(): Promise<ApplicationPublishResponse> {
    this.requireAuthentication();
    throw new ApiRequestError(undefined, '本地演示模式不连接真实发布 API。', 'unavailable', 'stub_unavailable');
  }

  async createSourceUpload(_input: SourceUploadInput, _signal?: AbortSignal): Promise<SourceUploadResponse> {
    this.requireAuthentication();
    return this.domainAndUploadUnavailable();
  }

  async getSourceUpload(_uploadId: string, _signal?: AbortSignal): Promise<SourceUploadResponse> {
    this.requireAuthentication();
    return this.domainAndUploadUnavailable();
  }

  subscribeToPublishEvents(operationId: string, listener: PublishEventListener, onStateChange?: (state: PublishConnectionState) => void): () => void {
    onStateChange?.('connecting');
    const listeners = this.listeners.get(operationId) ?? new Set<PublishEventListener>();
    listeners.add(listener);
    this.listeners.set(operationId, listeners);
    onStateChange?.('connected');
    return () => {
      listeners.delete(listener);
      if (listeners.size === 0) this.listeners.delete(operationId);
      onStateChange?.('closed');
    };
  }

  async getApplicationOperations(): Promise<ApplicationOperationsResult> {
    this.requireAuthentication();
    return operationsUnavailable();
  }

  async getApplicationUsage(): Promise<ApplicationUsageResult> {
    this.requireAuthentication();
    return usageUnavailable();
  }

  async getSystemStatus(): Promise<SystemStatusResult> {
    this.requireAuthentication();
    return { status: 'unavailable', message: '本地演示模式不连接真实系统状态 API。' };
  }

  async requestApplicationOperation(): Promise<OperationRequestResult> {
    this.requireAuthentication();
    return requestUnavailable();
  }

  private emit(event: PublishEvent): void {
    const application = this.applications.find((item) => item.id === event.applicationId);
    if (application) {
      application.publishing = applyPublishingEvent(application.publishing ?? createPublishingSnapshot(), event);
      application.updatedAt = event.occurredAt;
      if (event.status === 'succeeded') {
        application.runtimeStatus = 'running';
        application.runtimeReady = true;
        application.serving = false;
      }
    }
    this.listeners.get(event.operationId)?.forEach((listener) => listener(event));
  }
}

export function createConfiguredApiClient(options: Pick<RestApiClientOptions, 'onUnauthorized'> = {}): ApiClient {
  return import.meta.env.VITE_API_MODE === 'live' ? new RestApiClient(options) : new StubApiClient();
}
