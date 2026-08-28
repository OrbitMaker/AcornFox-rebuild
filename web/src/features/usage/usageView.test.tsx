import { renderToStaticMarkup } from 'react-dom/server';
import { OperationsUsageView, UsageView } from './UsageView';
import { formatUsageValue, usageFactIdentity, usagePercent, type ApplicationUsageFact } from './usageFacts';

const facts: ApplicationUsageFact = {
  version: 'usage-v5', observedAt: '2026-08-25T02:00:00.000Z', applicationId: 'app_docs', applicationName: '团队知识库', ai: 'disabled',
  services: [{
    id: 'api', name: 'api', releaseId: 'rel-12', runtime: '运行 3 小时 20 分', startedAt: '2026-08-24T22:40:00.000Z',
    actual: { cpu: { actual: 420, limit: 1000, unit: 'mCPU' }, memory: { actual: 512, limit: 1024, unit: 'MiB' }, disk: { actual: 4, limit: 20, unit: 'GiB' }, network: { actual: 12, limit: 0, unit: 'MiB' } },
    average: { cpu: { actual: 300, limit: 1000, unit: 'mCPU' }, memory: { actual: 400, limit: 1024, unit: 'MiB' }, disk: { actual: 3, limit: 20, unit: 'GiB' }, network: { actual: 8, limit: 0, unit: 'MiB' } },
    peak: { cpu: { actual: 420, limit: 1000, unit: 'mCPU' }, memory: { actual: 512, limit: 1024, unit: 'MiB' }, disk: { actual: 4, limit: 20, unit: 'GiB' }, network: { actual: 12, limit: 0, unit: 'MiB' } },
    configured: { cpu: { actual: 1000, limit: 1000, unit: 'mCPU' }, memory: { actual: 1024, limit: 1024, unit: 'MiB' }, disk: { actual: 20, limit: 20, unit: 'GiB' }, network: { actual: 0, limit: 0, unit: 'MiB' } },
    trend: [{ observedAt: '2026-08-25T02:00:00.000Z', cpu: { actual: 420, limit: 1000, unit: 'mCPU' }, memory: { actual: 512, limit: 1024, unit: 'MiB' }, disk: { actual: 4, limit: 20, unit: 'GiB' }, network: { actual: 12, limit: 100, unit: 'MiB' } }],
    anomalies: [],
  }],
  anomalies: [{ id: 'a1', observedAt: '2026-08-25T01:58:00.000Z', severity: 'warning', summary: '内存使用接近配置上限', relatedServiceId: 'api', relatedReleaseId: 'rel-12' }],
};

describe('M5 usage views', () => {
  it('renders a plain-language summary and keeps AI disabled', () => {
    const markup = renderToStaticMarkup(<UsageView facts={facts} mode="normal" />);
    expect(markup).toContain('运行中的服务');
    expect(markup).toContain('CPU');
		expect(markup).toContain('420 mCPU');
		expect(markup).toContain('512 MiB');
    expect(markup).toContain('AI 分析已关闭');
    expect(markup).toContain('内存使用接近配置上限');
  });

  it('renders operations columns for service, release, runtime, actual, limit and trend', () => {
    const markup = renderToStaticMarkup(<OperationsUsageView facts={facts} />);
    expect(markup).toContain('按服务、发布和运行时长查看资源');
    expect(markup).toContain('资源实际值与配置上限');
    expect(markup).toContain('rel-12');
    expect(markup).toContain('启动于 2026-08-24T22:40:00.000Z');
    expect(markup).toContain('CPU 420 mCPU');
    expect(markup).toContain('关联服务 api');
  });

  it('uses a versioned fact identity and safe formatting helpers', () => {
    expect(usageFactIdentity(facts)).toBe('usage-v5@2026-08-25T02:00:00.000Z');
    expect(usagePercent(facts.services[0].actual.cpu)).toBe(42);
    expect(formatUsageValue({ actual: Number.NaN, limit: 1, unit: 'MiB' })).toBe('待确认');
    expect(renderToStaticMarkup(<UsageView facts={facts} mode="operations" />)).toContain('运维视图');
  });
});
