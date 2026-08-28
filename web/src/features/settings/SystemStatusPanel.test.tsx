import { renderToStaticMarkup } from 'react-dom/server';
import type { SystemStatusResult } from '../../api/types';
import { SystemStatusPanel } from './SystemStatusPanel';

const result: SystemStatusResult = {
  status: 'available',
  facts: {
    version: '1.1',
    node: { singleNode: true, instanceId: 'instance-1', nodeId: 'node-1', readiness: 'ready' },
    platformDomain: { status: 'unconfigured', baseDomain: null },
    webhooks: { status: 'unconfigured', enabledCount: 0 },
    backup: { status: 'not_installed' },
    alerts: { status: 'not_installed' },
  },
};

describe('SystemStatusPanel', () => {
  it('renders only the API facts and explicit not-installed boundaries', () => {
    const html = renderToStaticMarkup(<SystemStatusPanel result={result} loading={false} />);
    expect(html).toContain('单节点 · 就绪');
    expect(html).toContain('实例 / 节点 ID');
    expect(html).toContain('未配置 · 未配置');
    expect(html).toContain('0 个启用');
    expect(html).toContain('未安装（后续 Gate 7）');
    expect(html).not.toContain('运行正常');
  });

  it('keeps loading and unavailable states explicit', () => {
    expect(renderToStaticMarkup(<SystemStatusPanel loading result={undefined} />)).toContain('role="status"');
    expect(renderToStaticMarkup(<SystemStatusPanel loading={false} result={{ status: 'unavailable', message: '状态暂时不可用。' }} />)).toContain('role="alert"');
  });
});
