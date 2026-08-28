import type { PublishingSnapshot, PublishEvent } from '../domain/publishing';
import type { DomainAccessSnapshot } from '../features/domains/domainAccess';
import type { ApplicationOperationsFact, OperationRequest } from '../features/operations/operationsView';
import type { ApplicationUsageFact } from '../features/usage/usageFacts';
import type { AIInterventionViewFact } from '../features/ai-interventions/aiInterventions';
import type { AIServiceSettingsFact } from '../features/settings/ai/AIServiceSettings';

export type SourceKind = 'git' | 'folder' | 'archive';
export type RuntimeStatus = 'running' | 'attention' | 'partial' | 'stopped' | 'unknown';

export interface ApplicationSource {
  kind: SourceKind;
  locator?: string;
  ref?: string;
}

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
  source: ApplicationSource;
  branch?: string;
  runtime?: {
    cpuMillicores: number;
    memoryMb: number;
  };
}

export interface CreateApplicationResponse {
  application: ApplicationSummary;
  operationId: string;
}

export interface ApplicationListResponse {
  items: ApplicationSummary[];
  nextCursor?: string;
}

export type PublishEventListener = (event: PublishEvent) => void;

/** The actor context is a request claim; the control plane must authorize it. */
export interface OperationActor {
  actor: string;
  role: 'operator' | 'viewer';
}

export type ApplicationOperationsResult =
  | { status: 'available'; facts: ApplicationOperationsFact }
  | { status: 'unavailable'; message: string };

export type ApplicationUsageResult =
  | { status: 'available'; facts: ApplicationUsageFact }
  | { status: 'unavailable'; message: string };

export type AIInterventionResult = { status: 'available'; facts: AIInterventionViewFact } | { status: 'unavailable'; message: string };
export type AISettingsResult = { status: 'available'; settings: AIServiceSettingsFact } | { status: 'unavailable'; message: string };

/** Accepted means queued only. A newer facts version is required to show completion. */
export type OperationRequestResult =
  | { status: 'accepted'; operationId?: string; message: string }
  | { status: 'unavailable'; message: string };

export interface ApiClient {
  listApplications(signal?: AbortSignal): Promise<ApplicationListResponse>;
  createApplication(input: CreateApplicationInput, signal?: AbortSignal): Promise<CreateApplicationResponse>;
  subscribeToPublishEvents(operationId: string, listener: PublishEventListener): () => void;
  getApplicationOperations(applicationId: string, signal?: AbortSignal): Promise<ApplicationOperationsResult>;
  getApplicationUsage(applicationId: string, mode: 'normal' | 'operations', signal?: AbortSignal): Promise<ApplicationUsageResult>;
  getAIInterventions(applicationId: string, mode: 'ordinary' | 'operator', signal?: AbortSignal): Promise<AIInterventionResult>;
  getAISettings(signal?: AbortSignal): Promise<AISettingsResult>;
  requestApplicationOperation(applicationId: string, request: OperationRequest, actor: OperationActor, signal?: AbortSignal): Promise<OperationRequestResult>;
}
