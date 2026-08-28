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
  AIInterventionResult,
  AISettingsResult,
  CreateApplicationInput,
  CreateApplicationResponse,
  OperationRequestResult,
  PublishEventListener,
} from './types';
import { CSRF_COOKIE_NAME, CSRF_HEADER_NAME, type AuthLoginInput, type AuthSession, type PasswordChangeInput } from '../features/auth/auth';
import type { ApplicationUsageFact, UsageAnomaly, UsageMeasurement, UsageResourceMeasurements, UsageServiceFact, UsageTrendPoint } from '../features/usage/usageFacts';
import type { AIActionFact, AIInterventionFact, AIInterventionStatus, AIInterventionViewFact, AIPlanFact, AIRisk } from '../features/ai-interventions/aiInterventions';
import type { AIServiceSettingsFact } from '../features/settings/ai/AIServiceSettings';
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

const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL as string | undefined) ?? '/api/v1';

export class ApiRequestError extends Error {
  constructor(public readonly status: number, message: string) {
    super(message);
    this.name = 'ApiRequestError';
  }
}

function isWriteMethod(method: string | undefined): boolean {
  return ['POST', 'PUT', 'PATCH', 'DELETE'].includes((method ?? 'GET').toUpperCase());
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

function requestError(status: number, fallback: string): ApiRequestError {
  if (status === 401) return new ApiRequestError(status, '管理员会话已失效，请重新登录。');
  if (status === 429) return new ApiRequestError(status, '请求过于频繁，请稍后再试。');
  if (status === 503) return new ApiRequestError(status, '控制面暂时不可用，请稍后重试。');
  return new ApiRequestError(status, fallback);
}

function withRequestDefaults(init: RequestInit = {}): RequestInit {
  const headers = new Headers(init.headers);
  if (isWriteMethod(init.method)) {
    const csrf = readCookie(CSRF_COOKIE_NAME);
    if (csrf) headers.set(CSRF_HEADER_NAME, csrf);
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

function normalizeApplication(value: unknown): ApplicationSummary {
  if (!isRecord(value) || typeof value.id !== 'string' || typeof value.name !== 'string') {
    throw new Error('OpenAPI response contained an invalid application');
  }
  const source = isRecord(value.source) && (value.source.kind === 'git' || value.source.kind === 'folder' || value.source.kind === 'archive')
    ? {
      kind: value.source.kind as ApplicationSource['kind'],
      locator: typeof value.source.locator === 'string' ? value.source.locator : undefined,
      ref: typeof value.source.ref === 'string' ? value.source.ref : undefined,
    }
    : { kind: 'git' as const };
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
  };
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

function isAIRisk(value: unknown): value is AIRisk { return value === 'R0' || value === 'R1' || value === 'R2' || value === 'R3'; }
function isAIStatus(value: unknown): value is AIInterventionStatus { return value === 'manual_fallback' || value === 'awaiting_confirmation' || value === 'controller_handoff' || value === 'running' || value === 'succeeded' || value === 'failed' || value === 'rolled_back'; }
function asAIAction(value: unknown): AIActionFact { if (!isRecord(value) || typeof value.tool_id !== 'string' || typeof value.tool_version !== 'string' || !isAIRisk(value.risk) || typeof value.expected_result !== 'string' || typeof value.validation_id !== 'string') throw new Error('AI plan contained an invalid action'); return { toolId: value.tool_id, toolVersion: value.tool_version, risk: value.risk, expectedResult: value.expected_result, validationId: value.validation_id }; }
function asAIPlan(value: unknown): AIPlanFact | undefined { if (value === undefined) return undefined; if (!isRecord(value) || typeof value.id !== 'string' || value.schema_version !== '1.0' || typeof value.policy_version !== 'string' || !finiteNonNegative(value.confidence) || typeof value.requires_user_confirmation !== 'boolean' || !Array.isArray(value.assumptions) || !Array.isArray(value.actions)) throw new Error('AI plan did not match the strict schema'); return { id: value.id, schemaVersion: '1.0', policyVersion: value.policy_version, confidence: value.confidence, requiresUserConfirmation: value.requires_user_confirmation, assumptions: value.assumptions.filter((item): item is string => typeof item === 'string'), actions: value.actions.map(asAIAction) }; }
function asAIIntervention(value: unknown): AIInterventionFact { if (!isRecord(value) || typeof value.id !== 'string' || typeof value.application_id !== 'string' || typeof value.task_type !== 'string' || !isAIStatus(value.status) || typeof value.reason !== 'string' || typeof value.summary !== 'string' || typeof value.suggestion !== 'string' || typeof value.requires_user_action !== 'boolean' || typeof value.controller_handoff !== 'boolean' || typeof value.rolled_back !== 'boolean' || typeof value.created_at !== 'string') throw new Error('AI intervention fact is invalid'); return { id: value.id, applicationId: value.application_id, taskType: value.task_type, status: value.status, reason: value.reason, summary: value.summary, suggestion: value.suggestion, requiresUserAction: value.requires_user_action, controllerHandoff: value.controller_handoff, provider: typeof value.provider === 'string' ? value.provider : undefined, model: typeof value.model === 'string' ? value.model : undefined, profile: typeof value.profile === 'string' ? value.profile : undefined, contextManifestDigest: typeof value.context_manifest_digest === 'string' ? value.context_manifest_digest : undefined, plan: asAIPlan(value.plan), evidence: Array.isArray(value.evidence) ? value.evidence.map((item) => isRecord(item) && typeof item.id === 'string' ? item.id : '').filter(Boolean) : [], tokens: finiteNonNegative(value.tokens) ? value.tokens : 0, durationMs: finiteNonNegative(value.duration_ms) ? value.duration_ms : 0, rolledBack: value.rolled_back, ruleCandidateId: typeof value.rule_candidate_id === 'string' ? value.rule_candidate_id : undefined, createdAt: value.created_at }; }
function asAIInterventionView(value: unknown): AIInterventionViewFact { if (!isRecord(value) || typeof value.version !== 'string' || (value.mode !== 'ordinary' && value.mode !== 'operator') || (value.ai_status !== 'disabled' && value.ai_status !== 'unavailable' && value.ai_status !== 'available') || !Array.isArray(value.items)) throw new Error('AI intervention view is invalid'); const count = (name: string) => finiteNonNegative(value[name]) ? value[name] as number : 0; return { version: value.version, mode: value.mode, aiStatus: value.ai_status, items: value.items.map(asAIIntervention), successCount: count('success_count'), failureCount: count('failure_count'), rollbackCount: count('rollback_count'), candidateCount: count('candidate_count'), totalTokens: count('total_tokens'), totalDurationMs: count('total_duration_ms') }; }
function asAISettings(value: unknown): AIServiceSettingsFact { if (!isRecord(value) || typeof value.version !== 'string' || typeof value.enabled !== 'boolean' || (value.status !== 'disabled' && value.status !== 'unavailable' && value.status !== 'available') || (value.profile !== 'china' && value.profile !== 'global' && value.profile !== 'local' && value.profile !== 'disabled') || typeof value.provider !== 'string' || typeof value.model !== 'string' || !Array.isArray(value.data_scopes) || !finiteNonNegative(value.max_tokens) || !finiteNonNegative(value.max_duration_ms) || !finiteNonNegative(value.cooldown_seconds) || typeof value.cache_enabled !== 'boolean' || typeof value.external_calls !== 'boolean') throw new Error('AI service settings are invalid'); return { version: value.version, enabled: value.enabled, status: value.status, profile: value.profile, provider: value.provider, model: value.model, dataScopes: value.data_scopes.filter((item): item is string => typeof item === 'string'), maxTokens: value.max_tokens, maxDurationMs: value.max_duration_ms, cooldownSeconds: value.cooldown_seconds, cacheEnabled: value.cache_enabled, externalCalls: value.external_calls }; }
function aiUnavailable(): AIInterventionResult { return { status: 'unavailable', message: 'AI 已关闭或尚未组合；标准发布与运维继续使用确定性流程。' }; }
function aiSettingsUnavailable(): AISettingsResult { return { status: 'unavailable', message: 'AI 服务设置尚未由控制面组合。' }; }

function operationIdempotencyKey(applicationId: string): string {
  const suffix = typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function'
    ? crypto.randomUUID()
    : `${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
  return `m4-operation:${applicationId}:${suffix}`;
}

export interface RestApiClientOptions {
  baseUrl?: string;
  fetchImpl?: typeof fetch;
  eventSourceFactory?: (url: string, init?: EventSourceInit) => EventSource;
  eventsUrl?: (operationId: string, baseUrl: string) => string;
  onUnauthorized?: () => void;
}

export class RestApiClient implements ApiClient {
  readonly authMode = 'live' as const;
  private readonly baseUrl: string;
  private readonly fetchImpl: typeof fetch;
  private readonly eventSourceFactory: (url: string, init?: EventSourceInit) => EventSource;
  private readonly eventsUrl: (operationId: string, baseUrl: string) => string;
  private readonly onUnauthorized?: () => void;

  constructor(options: RestApiClientOptions = {}) {
    this.baseUrl = (options.baseUrl ?? API_BASE_URL).replace(/\/$/, '');
    this.fetchImpl = options.fetchImpl ?? fetch;
    this.eventSourceFactory = options.eventSourceFactory ?? ((url, init) => new EventSource(url, init));
    this.eventsUrl = options.eventsUrl ?? ((operationId, baseUrl) => `${baseUrl}/events?operation_id=${encodeURIComponent(operationId)}`);
    this.onUnauthorized = options.onUnauthorized;
  }

  private async request(path: string, init: RequestInit = {}, notifyUnauthorized = true): Promise<Response> {
    const response = await this.fetchImpl(`${this.baseUrl}${path}`, withRequestDefaults(init));
    if (response.status === 401 && notifyUnauthorized) this.onUnauthorized?.();
    return response;
  }

  async getSession(signal?: AbortSignal): Promise<AuthSession> {
    const response = await this.request('/auth/session', { signal }, false);
    if (response.status === 401) return { authenticated: false, mode: this.authMode };
    if (!response.ok) throw requestError(response.status, 'Unable to load administrator session');
    return asAuthSession(await response.json(), this.authMode);
  }

  async login(input: AuthLoginInput, signal?: AbortSignal): Promise<AuthSession> {
    const response = await this.request('/auth/login', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(input),
      signal,
    });
    if (!response.ok) throw requestError(response.status, 'Administrator login was not accepted');
    return asAuthSession(await response.json(), this.authMode);
  }

  async logout(signal?: AbortSignal): Promise<void> {
    const response = await this.request('/auth/logout', { method: 'POST', signal });
    if (!response.ok && response.status !== 401) throw requestError(response.status, 'Logout was not completed');
  }

  async changePassword(input: PasswordChangeInput, signal?: AbortSignal): Promise<AuthSession> {
    const response = await this.request('/auth/password', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ current_password: input.currentPassword, new_password: input.newPassword }),
      signal,
    });
    if (response.status === 204) return { authenticated: false, mode: this.authMode };
    if (!response.ok) throw requestError(response.status, 'Password rotation was not completed');
    return asAuthSession(await response.json(), this.authMode);
  }

  async listApplications(signal?: AbortSignal): Promise<ApplicationListResponse> {
    const response = await this.request('/applications', { signal });
    if (!response.ok) throw requestError(response.status, 'Unable to list applications');
    return asApplicationList(await response.json());
  }

  async createApplication(input: CreateApplicationInput, signal?: AbortSignal): Promise<CreateApplicationResponse> {
    const response = await this.request('/applications', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(input),
      signal,
    });
    if (!response.ok) throw requestError(response.status, 'Unable to create application');
    return asCreateApplicationResponse(await response.json());
  }

  subscribeToPublishEvents(operationId: string, listener: PublishEventListener): () => void {
    const source = this.eventSourceFactory(this.eventsUrl(operationId, this.baseUrl), { withCredentials: true });
    const onMessage = (message: MessageEvent<string>) => {
      try {
        listener(asPublishEvent(JSON.parse(message.data) as unknown));
      } catch {
        // The controller owns event validity. Keep the stream alive and let the
        // next valid event reconcile the UI after a malformed payload.
      }
    };
    source.addEventListener('message', onMessage);
    return () => {
      source.removeEventListener('message', onMessage);
      source.close();
    };
  }

  async getApplicationOperations(applicationId: string, signal?: AbortSignal): Promise<ApplicationOperationsResult> {
    const response = await this.request(`/applications/${encodeURIComponent(applicationId)}/operations`, { signal });
    if (response.status === 404 || response.status === 501 || response.status === 503) return operationsUnavailable();
    if (!response.ok) throw requestError(response.status, 'Unable to load operations facts');
    return { status: 'available', facts: asApplicationOperationsFact(await response.json()) };
  }

  async getApplicationUsage(applicationId: string, mode: 'normal' | 'operations', signal?: AbortSignal): Promise<ApplicationUsageResult> {
    const response = await this.request(`/applications/${encodeURIComponent(applicationId)}/usage?mode=${encodeURIComponent(mode)}`, { signal });
    if (response.status === 404 || response.status === 501 || response.status === 503) return usageUnavailable();
    if (!response.ok) throw requestError(response.status, 'Unable to load usage facts');
    return { status: 'available', facts: asApplicationUsageFact(await response.json()) };
  }

  async getAIInterventions(applicationId: string, mode: 'ordinary' | 'operator', signal?: AbortSignal): Promise<AIInterventionResult> {
    const response = await this.request(`/applications/${encodeURIComponent(applicationId)}/ai/interventions?mode=${encodeURIComponent(mode)}`, { signal });
    if (response.status === 404 || response.status === 501 || response.status === 503) return aiUnavailable();
    if (!response.ok) throw requestError(response.status, 'Unable to load AI intervention facts');
    return { status: 'available', facts: asAIInterventionView(await response.json()) };
  }

  async getAISettings(signal?: AbortSignal): Promise<AISettingsResult> {
    const response = await this.request('/settings/ai', { signal });
    if (response.status === 404 || response.status === 501 || response.status === 503) return aiSettingsUnavailable();
    if (!response.ok) throw requestError(response.status, 'Unable to load AI service settings');
    return { status: 'available', settings: asAISettings(await response.json()) };
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
    if (!response.ok) throw requestError(response.status, `Unable to request ${request.action}`);
    const body: unknown = await response.json();
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
      source: { ...input.source },
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

  subscribeToPublishEvents(operationId: string, listener: PublishEventListener): () => void {
    const listeners = this.listeners.get(operationId) ?? new Set<PublishEventListener>();
    listeners.add(listener);
    this.listeners.set(operationId, listeners);
    return () => {
      listeners.delete(listener);
      if (listeners.size === 0) this.listeners.delete(operationId);
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

  async getAIInterventions(): Promise<AIInterventionResult> { this.requireAuthentication(); return aiUnavailable(); }

  async getAISettings(): Promise<AISettingsResult> { this.requireAuthentication(); return aiSettingsUnavailable(); }

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
