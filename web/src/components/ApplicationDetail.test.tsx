import { renderToStaticMarkup } from 'react-dom/server';
import type { ApplicationDetail as ApplicationDetailFact, ApplicationSummary } from '../api/types';
import { ApplicationDetail } from './ApplicationDetail';

const application: ApplicationSummary = {
  id: 'app-1',
  name: 'Portal',
  slug: 'portal',
  source: { kind: 'git', locator: 'https://git.example.test/repo.git', ref: 'main' },
  runtimeStatus: 'running',
  runtimeReady: true,
  serving: true,
  updatedAt: '2026-08-28T00:00:00Z',
};

const detail: ApplicationDetailFact = {
  id: 'app-1',
  name: 'Portal',
  createdAt: '2026-08-27T00:00:00Z',
  updatedAt: '2026-08-28T00:00:00Z',
  sourceUploadId: 'upload-1',
  access: {
    runtimeReady: true,
    ipFallback: '198.51.100.20',
    platformAddress: null,
    customDomains: [],
    route: { desired: true, serving: true, routeId: 'route-1' },
    certificate: { status: 'ready', subject: 'portal.example.com', notAfter: '2027-08-28T00:00:00Z' },
    serving: true,
  },
};

describe('ApplicationDetail', () => {
  it('guides the user when no application is selected', () => {
    expect(renderToStaticMarkup(<ApplicationDetail loading={false} onRefresh={() => undefined} />)).toContain('请先从应用列表选择一个应用');
  });

  it('renders the server application detail and access facts', () => {
    const markup = renderToStaticMarkup(<ApplicationDetail application={application} detail={detail} loading={false} onRefresh={() => undefined} />);

    expect(markup).toContain('upload-1');
    expect(markup).toContain('198.51.100.20');
    expect(markup).toContain('正在服务');
    expect(markup).toContain('app-1');
  });

  it('renders a safe retry state for detail failures', () => {
    const markup = renderToStaticMarkup(<ApplicationDetail application={application} loading={false} error={new Error('detail unavailable')} onRefresh={() => undefined} />);

    expect(markup).toContain('请求未完成');
    expect(markup).toContain('detail unavailable');
  });
});
