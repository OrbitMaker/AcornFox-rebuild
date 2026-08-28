import { renderToStaticMarkup } from 'react-dom/server';
import { ApiRequestError } from '../../api/errors';
import type { ApplicationAccessResponse, ApplicationDomain, PlatformDomainSettingsResponse } from '../../api/types';
import { DomainManagementPanel } from './DomainManagementWorkspace';

const platform = (status: PlatformDomainSettingsResponse['status']): PlatformDomainSettingsResponse => ({
  status,
  baseDomain: 'example.com',
  consoleDomain: 'console.example.com',
  wildcardPattern: '*.apps.example.com',
  verification: { method: 'cname', status, name: 'console.example.com', value: 'ingress.example.com', observedAt: '2026-08-28T00:00:00Z' },
  certificate: { status: status === 'ready' ? 'ready' : status === 'failed' ? 'failed' : status === 'certificate_pending' ? 'issuing' : 'pending', subject: '*.apps.example.com', notAfter: '2027-08-28T00:00:00Z' },
  failure: status === 'failed' ? { code: 'certificate_failed', message: '证书服务暂时失败', retryable: true } : null,
  nextAction: status === 'ready' ? 'ready' : status === 'failed' ? 'retry' : status === 'certificate_pending' ? 'wait_for_certificate' : status === 'verifying' ? 'wait_for_verification' : 'configure_base_domain',
});

const customDomain: ApplicationDomain = {
  id: 'domain-1',
  hostname: 'www.example.com',
  kind: 'custom',
  status: 'failed',
  cnameTarget: 'ingress.example.com',
  verification: { method: 'cname', status: 'failed', name: 'www.example.com', value: 'ingress.example.com', observedAt: '2026-08-28T00:00:00Z' },
  certificate: { status: 'failed', subject: 'www.example.com', notAfter: null },
  failure: { code: 'dns_not_ready', message: '尚未观测到 CNAME', retryable: true },
  serving: false,
};

const access: ApplicationAccessResponse = {
  runtimeReady: true,
  ipFallback: '198.51.100.20',
  platformAddress: { ...customDomain, id: 'platform-1', hostname: 'app.apps.example.com', kind: 'platform', status: 'ready', failure: null, serving: true },
  customDomains: [customDomain],
  route: { desired: true, serving: false, routeId: 'route-1' },
  certificate: { status: 'failed', subject: 'www.example.com', notAfter: null },
  serving: false,
};

const panelProps = {
  applicationId: 'app-1',
  domains: [customDomain],
  access,
  loading: false,
  baseDomain: 'example.com',
  hostname: '',
  onBaseDomainChange: () => undefined,
  onHostnameChange: () => undefined,
  onSavePlatform: () => undefined,
  onBindDomain: () => undefined,
  onRefresh: () => undefined,
  onRetryPlatform: () => undefined,
  onVerify: () => undefined,
  onUnbind: () => undefined,
  onCopyCname: () => undefined,
};

describe('DomainManagementPanel', () => {
  it.each(['pending', 'verifying', 'certificate_pending', 'ready', 'failed'] as const)('renders platform lifecycle state %s from API data', (status) => {
    const markup = renderToStaticMarkup(<DomainManagementPanel {...panelProps} platform={platform(status)} />);

    expect(markup).toContain('平台基础域名');
    expect(markup).toContain('example.com');
    expect(markup).toContain('*.apps.example.com');
    expect(markup).toContain('CNAME');
  });

  it('renders domain actions, CNAME copy, failure and IP fallback boundaries', () => {
    const markup = renderToStaticMarkup(<DomainManagementPanel
      {...panelProps}
      platform={platform('ready')}
      actionError={new ApiRequestError(429, '请求过于频繁，请稍后再试。', 'rate', 'rate_limited')}
      hostnameNotice="提交时将使用：www.example.com"
    />);

    expect(markup).toContain('复制 CNAME');
    expect(markup).toContain('重试验证');
    expect(markup).toContain('解绑');
    expect(markup).toContain('解绑不会影响 IP fallback 或平台地址');
    expect(markup).toContain('198.51.100.20');
    expect(markup).toContain('请求过于频繁');
    expect(markup).toContain('label');
  });

  it.each(['pending', 'verifying', 'certificate_pending', 'ready', 'failed'] as const)('renders application domain state %s from API data', (status) => {
    const markup = renderToStaticMarkup(<DomainManagementPanel
      {...panelProps}
      platform={platform('ready')}
      domains={[{ ...customDomain, status, verification: { ...customDomain.verification, status } }]}
    />);

    expect(markup).toContain('www.example.com');
    expect(markup).toContain(status === 'pending' ? '待处理' : status === 'verifying' ? '验证中' : status === 'certificate_pending' ? '证书处理中' : status === 'ready' ? '已就绪' : '失败');
  });

  it('shows Stub or unavailable state without a false success status', () => {
    const markup = renderToStaticMarkup(<DomainManagementPanel
      {...panelProps}
      platform={null}
      domains={null}
      access={null}
      platformError={new ApiRequestError(undefined, '本地演示模式不连接真实域名或上传 API。', 'unavailable', 'stub_unavailable')}
      domainsError={new ApiRequestError(503, '控制面暂时不可用，请稍后重试。', 'unavailable', 'dependency_unavailable')}
      accessError={new ApiRequestError(503, '控制面暂时不可用，请稍后重试。', 'unavailable', 'dependency_unavailable')}
    />);

    expect(markup).toContain('不可用');
    expect(markup).toContain('本地演示模式不连接真实域名 API');
    expect(markup).not.toContain('域名已就绪');
  });
});
