/**
 * The UI only exposes the five product publishing states. Operational facts
 * such as RUNTIME_READY and SERVING belong to separate API fields and must
 * not be inferred from a successful publish event.
 */
export const PUBLISHING_STATUSES = [
  'preparing',
  'building',
  'deploying',
  'succeeded',
  'failed',
] as const;

export type PublishingStatus = (typeof PUBLISHING_STATUSES)[number];

export type PublishEventKind =
  | 'operation.created'
  | 'build.started'
  | 'deployment.started'
  | 'operation.succeeded'
  | 'operation.failed';

export const PUBLISH_EVENT_KINDS = [
  'operation.created',
  'build.started',
  'deployment.started',
  'operation.succeeded',
  'operation.failed',
] as const satisfies readonly PublishEventKind[];

export interface PublishEvent {
  id: string;
  operationId: string;
  applicationId: string;
  sequence: number;
  occurredAt: string;
  kind: PublishEventKind;
  status: PublishingStatus;
  message?: string;
  evidenceIds?: string[];
}

export interface PublishingSnapshot {
  status: PublishingStatus;
  sequence: number;
  lastEventId?: string;
  message?: string;
  evidenceIds: string[];
}

export const PUBLISHING_STATUS_LABELS: Record<PublishingStatus, string> = {
  preparing: '准备中',
  building: '构建中',
  deploying: '部署中',
  succeeded: '部署成功',
  failed: '部署失败',
};

export const PUBLISHING_STATUS_DESCRIPTIONS: Record<PublishingStatus, string> = {
  preparing: '正在检查来源和发布定义',
  building: '正在受限构建并收集证据',
  deploying: '正在部署到预设单机',
  succeeded: '已完成独立验证',
  failed: '发布未完成，请查看事件和证据',
};

const ALLOWED_TRANSITIONS: Record<PublishingStatus, readonly PublishingStatus[]> = {
  preparing: ['preparing', 'building', 'failed'],
  building: ['building', 'deploying', 'failed'],
  deploying: ['deploying', 'succeeded', 'failed'],
  succeeded: ['succeeded'],
  failed: ['failed'],
};

/**
 * Events are monotonic by sequence. A terminal state accepts no later event;
 * this protects the projection from stale SSE reconnects and duplicate
 * delivery without hiding the actual event stream from the user.
 */
export function isValidPublishingTransition(
  from: PublishingStatus,
  to: PublishingStatus,
): boolean {
  return ALLOWED_TRANSITIONS[from].includes(to);
}

export function createPublishingSnapshot(
  status: PublishingStatus = 'preparing',
): PublishingSnapshot {
  return {
    status,
    sequence: 0,
    evidenceIds: [],
  };
}

export function applyPublishingEvent(
  snapshot: PublishingSnapshot,
  event: PublishEvent,
): PublishingSnapshot {
  if (event.sequence <= snapshot.sequence) return snapshot;
  if (!isValidPublishingTransition(snapshot.status, event.status)) return snapshot;

  return {
    status: event.status,
    sequence: event.sequence,
    lastEventId: event.id,
    message: event.message,
    evidenceIds: event.evidenceIds ?? snapshot.evidenceIds,
  };
}

export function publishingStatusLabel(status: PublishingStatus): string {
  return PUBLISHING_STATUS_LABELS[status];
}

export function isPublishingStatus(value: unknown): value is PublishingStatus {
  return typeof value === 'string' && (PUBLISHING_STATUSES as readonly string[]).includes(value);
}

export function isPublishEventKind(value: unknown): value is PublishEventKind {
  return typeof value === 'string' && (PUBLISH_EVENT_KINDS as readonly string[]).includes(value);
}

export function isPublishingTerminal(status: PublishingStatus): boolean {
  return status === 'succeeded' || status === 'failed';
}
