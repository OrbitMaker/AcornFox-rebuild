/** Read-only M5 usage projection supplied by the control plane. */
export type UsageMetric = 'cpu' | 'memory' | 'disk' | 'network';
export interface UsageMeasurement { actual: number; limit: number; unit: string }
export interface UsageResourceMeasurements { cpu: UsageMeasurement; memory: UsageMeasurement; disk: UsageMeasurement; network: UsageMeasurement }
export interface UsageTrendPoint extends UsageResourceMeasurements { observedAt: string }
export type UsageAnomalySeverity = 'info' | 'warning' | 'critical';
export interface UsageAnomaly { id: string; observedAt: string; severity: UsageAnomalySeverity; summary: string; relatedServiceId?: string; relatedReleaseId?: string }
export interface UsageServiceFact { id: string; name: string; releaseId: string; runtime: string; startedAt: string; actual: UsageResourceMeasurements; average: UsageResourceMeasurements; peak: UsageResourceMeasurements; configured: UsageResourceMeasurements; trend: readonly UsageTrendPoint[]; anomalies: readonly UsageAnomaly[] }
export interface ApplicationUsageFact { version: string; observedAt: string; applicationId: string; applicationName: string; services: readonly UsageServiceFact[]; anomalies: readonly UsageAnomaly[]; ai: 'disabled' }
export const USAGE_METRIC_LABELS: Record<UsageMetric, string> = { cpu: 'CPU', memory: '内存', disk: '磁盘', network: '网络' };
export const ANOMALY_SEVERITY_LABELS: Record<UsageAnomalySeverity, string> = { info: '提示', warning: '注意', critical: '异常' };
export function usageFactIdentity(fact: ApplicationUsageFact): string { return `${fact.version}@${fact.observedAt}`; }
export function usagePercent(measurement: UsageMeasurement): number | null {
  if (!Number.isFinite(measurement.actual) || !Number.isFinite(measurement.limit) || measurement.limit <= 0) return null;
  return Math.round((measurement.actual / measurement.limit) * 100);
}
export function formatUsageValue(measurement: UsageMeasurement): string { return Number.isFinite(measurement.actual) ? `${measurement.actual} ${measurement.unit}` : '待确认'; }
