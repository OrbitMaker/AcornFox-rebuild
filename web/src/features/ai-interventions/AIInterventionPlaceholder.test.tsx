import { renderToStaticMarkup } from 'react-dom/server';
import { AIInterventionPlaceholder } from './AIInterventionPlaceholder';

describe('M4 AI intervention placeholder', () => {
  it('is disabled presentation only and does not claim an AI action', () => {
    const markup = renderToStaticMarkup(<AIInterventionPlaceholder availability="disabled" />);

    expect(markup).toContain('AI 分析未配置');
    expect(markup).toContain('不依赖 AI');
    expect(markup).toContain('不会自动执行重启、重新部署、回滚');
    expect(markup).not.toContain('分析完成');
  });

  it('shows unavailable state without requesting a provider', () => {
    const markup = renderToStaticMarkup(<AIInterventionPlaceholder availability="unavailable" reason="Provider health check failed" />);

    expect(markup).toContain('AI 分析暂不可用');
    expect(markup).toContain('Provider health check failed');
  });
});
