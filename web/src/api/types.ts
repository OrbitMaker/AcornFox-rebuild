import type { PublishingSnapshot, PublishEvent } from '../domain/publishing';
import type { DomainAccessSnapshot } from '../features/domains/domainAccess';
import type { ApplicationOperationsFact, OperationRequest } from '../features/operations/operationsView';
import type { ApplicationUsageFact } from '../features/usage/usageFacts';
import type { AIInterventionViewFact } from '../features/ai-interventions/aiInterventions';
import type { AIServiceSettingsFact } from '../features/settings/ai/AIServiceSettings';
import type { AuthClient } from '../features/auth/auth';

export type SourceKind = 'git' | 'folder' | 'archive' | 'unknown';
export type RuntimeStatus = 'running' | 'attention' | 'partial' | 'stopped' | 'unknown';

export interface ApplicationSource {
  kind: SourceKind;
  uploadId?: string;
  locator?: string;
  ref?: string;
}

export type CreateApplicationSource =
  | { kind: 'upload'; uploadId: string }
  | { kind: 'git'; repositoryUrl: string; ref: string };

export interface ApplicationSummary {
  id: string;
  name: string;
  slug: string;
  source: ApplicationSource;
  runtimeStatus: RuntimeStatus;
  runtimeReady: boolean;
  serving: boolean;
  route?: string;
  access?: DomainAccessSnapshot;
  lastRelease?: {
    id: string;
    version: string;
    createdAt: string;
  };
  publishing?: PublishingSnapshot;
  operationId?: string;
  updatedAt: string;
}

export interface CreateApplicationInput {
  name: string;
  source: CreateApplicationSource;
  branch?: string;
  runtime?: {
    cpuMillicores: number;
    memoryMb: number;
  };
}

export interface CreateApplicationResponse {
  application: ApplicationSummary;
  operationId: string;
  environmentId?: string;
  sourceRevisionId?: string;
}

export interface ApplicationListResponse {
  items: ApplicationSummary[];
  nextCursor?: string;
}

export type DomainLifecycleStatus = 'pending' | 'verifying' | 'certificate_pending' | 'ready' | 'failed';
export type DomainVerificationMethod = 'dns_txt' | 'cname' | 'public_dns_read_only';
export type DomainKind = 'platform' | 'custom';

export interface DomainVerification {
  method: DomainVerificationMethod;
  status: DomainLifecycleStatus;
  name?: string | null;
  value?: string | null;
  observedAt?: string | null;
}

export interface CertificateStatus {
  status: 'pending' | 'issuing' | 'ready' | 'failed';
  subject?: string | null;
  notAfter?: string | null;
}

export interface FailureState {
  code: string;
  message: string;
  retryable?: boolean;
}

export interface PlatformDomainSettingsRequest {
  baseDomain: string;
}

export interface PlatformDomainSettingsResponse {
  status: DomainLifecycleStatus;
  baseDomain: string | null;
  consoleDomain: string | null;
  wildcardPattern: string | null;
  verification: DomainVerification;
  certificate: CertificateStatus;
  failure: FailureState | null;
  nextAction: 'configure_base_domain' | 'publish_verification_record' | 'wait_for_verification' | 'wait_for_certificate' | 'ready' | 'retry';
}

export interface ApplicationDomain {
  id: string;
  hostname: string;
  kind: DomainKind;
  status: DomainLifecycleStatus;
  cnameTarget: string | null;
  verification: DomainVerification;
  certificate: CertificateStatus;
  failure: FailureState | null;
  serving: boolean;
}

export interface ApplicationDomainsResponse {
  items: ApplicationDomain[];
}

export interface CustomDomainBindRequest {
  hostname: string;
}

export interface ApplicationDomainResponse {
  domain: ApplicationDomain;
}

export interface AccessRouteStatus {
  desired: boolean;
  serving: boolean;
  routeId?: string | null;
}

export interface ApplicationAccessResponse {
  runtimeReady: boolean;
  ipFallback: string | null;
  platformAddress: ApplicationDomain | null;
  customDomains: ApplicationDomain[];
  route: AccessRouteStatus;
  certificate: CertificateStatus;
  serving: boolean;
}

export type ApplicationPublishBuildKind = 'static' | 'dockerfile';

export interface ApplicationPublishInput {
  buildKind: ApplicationPublishBuildKind;
  contextPath: string;
  dockerfilePath?: string;
  serviceName: string;
  containerPort: number;
}

export interface ApplicationPublishResponse {
  status: 'deploying';
  operationId: string;
  releaseId: string;
  deploymentId: string;
  taskId: string;
  sourceRevisionId: string;
}

export interface ApplicationDetail {
  id: string;
  name: string;
  createdAt: string;
  updatedAt: string;
  sourceUploadId: string | null;
  access: ApplicationAccessResponse;
}

export interface SourceUploadManifestEntry {
  path: string;
  bytes: number;
  digest?: string;
}

export interface SourceUploadManifest {
  files: SourceUploadManifestEntry[];
}

export type SourceUploadArchiveInput = { mode: 'archive'; archive: File | Blob };
export type SourceUploadDirectoryInput = { mode: 'directory'; files: File[]; manifest: SourceUploadManifest };
export type SourceUploadInput = SourceUploadArchiveInput | SourceUploadDirectoryInput | FormData;

export interface SourceUploadResponse {
  uploadId: string;
  kind: 'archive' | 'directory';
  status: 'ready' | 'claimed' | 'expired' | 'failed';
  digest: string;
  bytes: number;
  fileCount: number;
  expiresAt: string;
}

export type PublishEventListener = (event: PublishEvent) => void;
export type PublishConnectionState = 'connecting' | 'connected' | 'retrying' | 'offline' | 'auth_required' | 'closed';

export type ApplicationOperationsResult =
  | { status: 'available'; facts: ApplicationOperationsFact }
  | { status: 'unavailable'; message: string };

export type ApplicationUsageResult =
  | { status: 'available'; facts: ApplicationUsageFact }
  | { status: 'unavailable'; message: string };

export type AIInterventionResult = { status: 'available'; facts: AIInterventionViewFact } | { status: 'unavailable'; message: string };
export type AISettingsResult = { status: 'available'; settings: AIServiceSettingsFact } | { status: 'unavailable'; message: string };

export type SystemStatusNodeReadiness = 'ready' | 'not_ready' | 'unconfigured';
export type SystemStatusPlatformDomain = 'unconfigured' | 'pending' | 'failed' | 'ready';
export type SystemStatusWebhooks = 'configured' | 'unconfigured';

export interface SystemStatusFact {
  version: string;
  node: {
    singleNode: true;
    instanceId: string | null;
    nodeId: string | null;
    readiness: SystemStatusNodeReadiness;
  };
  platformDomain: {
    status: SystemStatusPlatformDomain;
    baseDomain: string | null;
  };
  webhooks: {
    status: SystemStatusWebhooks;
    enabledCount: number;
  };
  backup: { status: 'not_installed' };
  alerts: { status: 'not_installed' };
}

export type SystemStatusResult =
  | { status: 'available'; facts: SystemStatusFact }
  | { status: 'unavailable'; message: string };

/** Accepted means queued only. A newer facts version is required to show completion. */
export type OperationRequestResult =
  | { status: 'accepted'; operationId?: string; message: string }
  | { status: 'unavailable'; message: string };

export interface ApiClient extends AuthClient {
  listApplications(signal?: AbortSignal): Promise<ApplicationListResponse>;
  createApplication(input: CreateApplicationInput, signal?: AbortSignal): Promise<CreateApplicationResponse>;
  getApplication(applicationId: string, signal?: AbortSignal): Promise<ApplicationDetail>;
  getPlatformDomainSettings(signal?: AbortSignal): Promise<PlatformDomainSettingsResponse>;
  putPlatformDomainSettings(input: PlatformDomainSettingsRequest, signal?: AbortSignal): Promise<PlatformDomainSettingsResponse>;
  listApplicationDomains(applicationId: string, signal?: AbortSignal): Promise<ApplicationDomainsResponse>;
  bindApplicationCustomDomain(applicationId: string, input: CustomDomainBindRequest, signal?: AbortSignal): Promise<ApplicationDomainResponse>;
  verifyApplicationDomain(applicationId: string, domainId: string, signal?: AbortSignal): Promise<ApplicationDomainResponse>;
  unbindApplicationDomain(applicationId: string, domainId: string, signal?: AbortSignal): Promise<void>;
  getApplicationAccess(applicationId: string, signal?: AbortSignal): Promise<ApplicationAccessResponse>;
  publishApplication(applicationId: string, input: ApplicationPublishInput, signal?: AbortSignal): Promise<ApplicationPublishResponse>;
  createSourceUpload(input: SourceUploadInput, signal?: AbortSignal): Promise<SourceUploadResponse>;
  getSourceUpload(uploadId: string, signal?: AbortSignal): Promise<SourceUploadResponse>;
  subscribeToPublishEvents(operationId: string, listener: PublishEventListener, onStateChange?: (state: PublishConnectionState) => void): () => void;
  getApplicationOperations(applicationId: string, signal?: AbortSignal): Promise<ApplicationOperationsResult>;
  getApplicationUsage(applicationId: string, mode: 'normal' | 'operations', signal?: AbortSignal): Promise<ApplicationUsageResult>;
  getAIInterventions(applicationId: string, mode: 'ordinary' | 'operator', signal?: AbortSignal): Promise<AIInterventionResult>;
  getAISettings(signal?: AbortSignal): Promise<AISettingsResult>;
  getSystemStatus(signal?: AbortSignal): Promise<SystemStatusResult>;
  requestApplicationOperation(applicationId: string, request: OperationRequest, signal?: AbortSignal): Promise<OperationRequestResult>;
}
