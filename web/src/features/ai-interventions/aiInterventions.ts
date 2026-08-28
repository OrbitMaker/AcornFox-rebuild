export type AIInterventionStatus = 'manual_fallback' | 'awaiting_confirmation' | 'controller_handoff' | 'running' | 'succeeded' | 'failed' | 'rolled_back';
export type AIRisk = 'R0' | 'R1' | 'R2' | 'R3';
export interface AIActionFact { toolId: string; toolVersion: string; risk: AIRisk; expectedResult: string; validationId: string }
export interface AIPlanFact { id: string; schemaVersion: '1.0'; policyVersion: string; confidence: number; requiresUserConfirmation: boolean; assumptions: readonly string[]; actions: readonly AIActionFact[] }
export interface AIInterventionFact { id: string; applicationId: string; taskType: string; status: AIInterventionStatus; reason: string; summary: string; suggestion: string; requiresUserAction: boolean; controllerHandoff: boolean; provider?: string; model?: string; profile?: string; contextManifestDigest?: string; plan?: AIPlanFact; evidence: readonly string[]; tokens: number; durationMs: number; rolledBack: boolean; ruleCandidateId?: string; createdAt: string }
export interface AIInterventionViewFact { version: string; mode: 'ordinary' | 'operator'; aiStatus: 'disabled' | 'unavailable' | 'available'; items: readonly AIInterventionFact[]; successCount: number; failureCount: number; rollbackCount: number; candidateCount: number; totalTokens: number; totalDurationMs: number }

export const AI_STATUS_LABELS: Record<AIInterventionStatus, string> = {
  manual_fallback: '转人工处理', awaiting_confirmation: '等待确认', controller_handoff: '转控制器确认', running: '受限验证中', succeeded: '验证通过', failed: '验证失败', rolled_back: '已回滚候选',
};

export function aiInterventionNeedsAttention(item: AIInterventionFact): boolean { return item.requiresUserAction || item.status === 'failed' || item.status === 'rolled_back' || item.status === 'awaiting_confirmation' || item.status === 'controller_handoff'; }
