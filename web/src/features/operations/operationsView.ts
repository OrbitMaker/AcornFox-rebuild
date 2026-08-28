/**
 * M4 views consume this immutable projection from the control plane. It is
 * intentionally not a client-side state machine: refresh/SSE owns new facts,
 * while UI actions only express an operation request to the caller.
 */
export type OperationsViewMode = 'normal' | 'operations';

export type ServiceHealth = 'healthy' | 'degraded' | 'unhealthy' | 'unknown';

export type OperationAction = 'restart' | 'redeploy' | 'rollback';

export type OperationActionStatus = 'idle' | 'pending' | 'running' | 'succeeded' | 'failed' | 'blocked';

export interface ActualServiceResources {
  cpuMillicores: number;
  memoryBytes: number;
  diskBytes: number;
  networkRxBytes: number;
  networkTxBytes: number;
  restartCount: number;
}

export interface ServiceOperationsFact {
  id: string;
  name: string;
  health: ServiceHealth;
  required: boolean;
  releaseId?: string;
  exitReason?: string;
  resources: ActualServiceResources;
}

export interface OperationActionFact {
  action: OperationAction;
  status: OperationActionStatus;
  operationId?: string;
  targetServiceId?: string;
  message?: string;
  enabled: boolean;
}

export interface ApplicationOperationsFact {
  /** Monotonic control-plane fact version shared by both views. */
  version: string;
  /** The control-plane observation timestamp, not the browser clock. */
  observedAt: string;
  applicationId: string;
  applicationName: string;
  serving: boolean;
  impact: string;
  nextStep: string;
  services: readonly ServiceOperationsFact[];
  actions: readonly OperationActionFact[];
  /** Code/config rollback never implies a database or volume rollback. */
  dataRollbackSupported: false;
}

export interface OperationRequest {
  action: OperationAction;
  targetServiceId?: string;
  expectedVersion: string;
}

const actionOrder: readonly OperationAction[] = ['restart', 'redeploy', 'rollback'];

export const OPERATION_ACTION_LABELS: Record<OperationAction, string> = {
  restart: '重启异常服务',
  redeploy: '重新部署',
  rollback: '回滚到上一成功版本',
};

export const OPERATION_ACTION_STATUS_LABELS: Record<OperationActionStatus, string> = {
  idle: '可执行',
  pending: '等待执行',
  running: '执行中',
  succeeded: '已完成',
  failed: '执行失败',
  blocked: '暂不可执行',
};

export const SERVICE_HEALTH_LABELS: Record<ServiceHealth, string> = {
  healthy: '健康',
  degraded: '降级',
  unhealthy: '异常',
  unknown: '待确认',
};

export function operationActionFacts(fact: ApplicationOperationsFact): readonly OperationActionFact[] {
  const byAction = new Map(fact.actions.map((action) => [action.action, action]));
  return actionOrder.flatMap((action) => {
    const value = byAction.get(action);
    return value === undefined ? [] : [value];
  });
}

export function operationRequestFor(
  fact: ApplicationOperationsFact,
  action: OperationActionFact,
): OperationRequest {
  return {
    action: action.action,
    targetServiceId: action.targetServiceId,
    expectedVersion: fact.version,
  };
}

/** Actions are disabled until a newer fact confirms the previous result. */
export function canRequestOperation(action: OperationActionFact): boolean {
  return action.enabled && action.status === 'idle';
}

export function operationFactIdentity(fact: ApplicationOperationsFact): string {
  return `${fact.version}@${fact.observedAt}`;
}

export function formatBytes(value: number): string {
  if (!Number.isFinite(value) || value < 0) return '待确认';
  if (value < 1024) return `${Math.round(value)} B`;
  const units = ['KiB', 'MiB', 'GiB', 'TiB'];
  let scaled = value;
  let unit = -1;
  do {
    scaled /= 1024;
    unit += 1;
  } while (scaled >= 1024 && unit < units.length - 1);
  return `${scaled >= 10 ? scaled.toFixed(0) : scaled.toFixed(1)} ${units[unit]}`;
}
