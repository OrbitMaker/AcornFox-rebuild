export type AIInterventionAvailability = 'disabled' | 'unavailable';

export interface AIInterventionPlaceholderProps {
  availability: AIInterventionAvailability;
  reason?: string;
}

const availabilityCopy: Record<AIInterventionAvailability, { title: string; detail: string }> = {
  disabled: {
    title: 'AI 分析未配置',
    detail: '当前实例未启用 AI 分析。应用运行、日志与安全操作不依赖 AI。',
  },
  unavailable: {
    title: 'AI 分析暂不可用',
    detail: 'AI 服务当前不可用；请继续依据控制面事实、日志和安全操作处理问题。',
  },
};

/** A M4 presentation-only placeholder. It neither fetches nor invokes any AI provider. */
export function AIInterventionPlaceholder({ availability, reason }: AIInterventionPlaceholderProps) {
  const copy = availabilityCopy[availability];
  return (
    <aside className="ai-intervention-placeholder" aria-label="AI 介入分析状态">
      <p className="eyebrow">AI 介入分析</p>
      <h2>{copy.title}</h2>
      <p>{reason ?? copy.detail}</p>
      <small>不会自动执行重启、重新部署、回滚或其他生产操作。</small>
    </aside>
  );
}
