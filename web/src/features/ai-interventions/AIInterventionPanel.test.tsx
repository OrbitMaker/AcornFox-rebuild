import { renderToStaticMarkup } from 'react-dom/server';
import { AIInterventionPanel } from './AIInterventionPanel';
import type { AIInterventionViewFact } from './aiInterventions';

const facts: AIInterventionViewFact = { version: 'ai-v1', mode: 'operator', aiStatus: 'available', successCount: 0, failureCount: 1, rollbackCount: 1, candidateCount: 1, totalTokens: 32, totalDurationMs: 20, items: [{ id: 'airec-1', applicationId: 'app-1', taskType: 'build_failure_diagnosis', status: 'rolled_back', reason: 'deterministic rule miss', summary: '受限测试未通过', suggestion: '检查候选差异', requiresUserAction: true, controllerHandoff: false, provider: 'fixture', model: 'deterministic', profile: 'local', contextManifestDigest: 'sha256:redacted', evidence: ['ev-verify'], tokens: 32, durationMs: 20, rolledBack: true, ruleCandidateId: 'candidate-1', createdAt: '2026-08-25T00:00:00Z', plan: { id: 'plan-1', schemaVersion: '1.0', policyVersion: 'policy-v1', confidence: .8, requiresUserConfirmation: false, assumptions: [], actions: [{ toolId: 'workspace.build_test', toolVersion: 'v1', risk: 'R1', expectedResult: 'test evidence', validationId: 'build-v1' }] } }] };

describe('M6 AI intervention views', () => {
  it('keeps ordinary output concise and honest', () => { const html = renderToStaticMarkup(<AIInterventionPanel facts={facts} mode="ordinary" />); expect(html).toContain('受限测试未通过'); expect(html).toContain('需要人工检查'); expect(html).not.toContain('Context manifest'); });
  it('shows redacted ledger details only in operator mode', () => { const html = renderToStaticMarkup(<AIInterventionPanel facts={facts} mode="operator" />); expect(html).toContain('workspace.build_test@v1'); expect(html).toContain('规则候选：candidate-1（尚未自动生效）'); expect(html).toContain('已执行'); });
  it('states that disabled AI is not a Golden Path dependency', () => { const disabled = { ...facts, aiStatus: 'disabled' as const, items: [] }; const html = renderToStaticMarkup(<AIInterventionPanel facts={disabled} mode="ordinary" />); expect(html).toContain('AI 已关闭'); expect(html).toContain('标准发布、运行与运维不依赖 AI'); });
});
