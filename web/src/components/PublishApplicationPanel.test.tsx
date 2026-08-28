import { renderToStaticMarkup } from 'react-dom/server';
import { vi } from 'vitest';
import { PublishApplicationPanel } from './PublishApplicationPanel';

describe('PublishApplicationPanel', () => {
  it('exposes safe defaults and does not claim runtime readiness', () => {
    const markup = renderToStaticMarkup(<PublishApplicationPanel applicationId="app-1" client={{ publishApplication: vi.fn() }} />);

    expect(markup).toContain('静态站点');
    expect(markup).toContain('value="."');
    expect(markup).toContain('value="web"');
    expect(markup).toContain('value="8080"');
    expect(markup).toContain('最长等待 10 分钟');
    expect(markup).toContain('接受不等于运行就绪');
  });
});
