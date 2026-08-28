import { AI_STATUS_LABELS, aiInterventionNeedsAttention, type AIInterventionFact, type AIInterventionViewFact } from './aiInterventions';

export function AIInterventionPanel({ facts, mode, onModeChange }: { facts: AIInterventionViewFact; mode: 'ordinary' | 'operator'; onModeChange?: (mode: 'ordinary' | 'operator') => void }) {
  return <section className="ai-intervention-panel" aria-labelledby="ai-intervention-heading">
    <header><div><p className="eyebrow">运行与运维</p><h2 id="ai-intervention-heading">AI 介入分析</h2><p>规则优先；AI 只处理未覆盖异常，不能直接修改生产。</p></div>{onModeChange && <div role="group" aria-label="AI 介入视图"><button type="button" aria-pressed={mode === 'ordinary'} onClick={() => onModeChange('ordinary')}>普通</button><button type="button" aria-pressed={mode === 'operator'} onClick={() => onModeChange('operator')}>运维</button></div>}</header>
    {facts.aiStatus !== 'available' && <aside role="status"><strong>{facts.aiStatus === 'disabled' ? 'AI 已关闭' : 'AI 当前不可用'}</strong><span>标准发布、运行与运维不依赖 AI。</span></aside>}
    {facts.items.length === 0 ? <p>暂无 AI 介入记录。</p> : <ul>{facts.items.map((item) => <li key={item.id}><OrdinaryIntervention item={item} />{mode === 'operator' && <OperatorIntervention item={item} />}</li>)}</ul>}
    {mode === 'operator' && <dl><div><dt>成功</dt><dd>{facts.successCount}</dd></div><div><dt>失败</dt><dd>{facts.failureCount}</dd></div><div><dt>回滚</dt><dd>{facts.rollbackCount}</dd></div><div><dt>规则候选</dt><dd>{facts.candidateCount}</dd></div><div><dt>Token</dt><dd>{facts.totalTokens}</dd></div></dl>}
  </section>;
}

function OrdinaryIntervention({ item }: { item: AIInterventionFact }) {
  return <article><header><strong>{AI_STATUS_LABELS[item.status]}</strong><time>{item.createdAt}</time></header><p>{item.summary}</p><small>原因：{item.reason}</small><p>建议：{item.suggestion}</p>{aiInterventionNeedsAttention(item) && <em>需要人工检查</em>}</article>;
}

function OperatorIntervention({ item }: { item: AIInterventionFact }) {
  return <details><summary>查看脱敏计划与证据</summary><dl><div><dt>Provider / 模型</dt><dd>{item.provider ?? '未调用'} / {item.model ?? '未调用'}</dd></div><div><dt>区域 Profile</dt><dd>{item.profile ?? 'disabled'}</dd></div><div><dt>Context manifest</dt><dd>{item.contextManifestDigest ?? '无'}</dd></div><div><dt>Token / 耗时</dt><dd>{item.tokens} / {item.durationMs} ms</dd></div><div><dt>回滚</dt><dd>{item.rolledBack ? '已执行' : '未执行'}</dd></div></dl>{item.plan && <section><h3>结构化计划 {item.plan.schemaVersion}</h3><p>置信度 {item.plan.confidence} · 策略 {item.plan.policyVersion}</p><ul>{item.plan.actions.map((action) => <li key={`${action.toolId}@${action.toolVersion}`}><code>{action.toolId}@{action.toolVersion}</code> {action.risk} · {action.expectedResult}</li>)}</ul></section>}<p>证据：{item.evidence.length ? item.evidence.join('、') : '无原始明文证据'}</p>{item.ruleCandidateId && <p>规则候选：{item.ruleCandidateId}（尚未自动生效）</p>}</details>;
}
