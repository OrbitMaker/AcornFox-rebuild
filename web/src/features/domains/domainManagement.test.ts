import { vi } from 'vitest';
import { ApiRequestError } from '../../api/errors';
import {
  bindCustomDomain,
  certificateStatusLabel,
  configurePlatformDomain,
  copyCnameTarget,
  domainManagementErrorMessage,
  domainStatusLabel,
  fallbackAccessNotice,
  normalizeHostnameInput,
  unbindDomain,
  verificationEvidenceSummary,
  verifyDomain,
} from './domainManagement';

describe('domain management helpers', () => {
  it('normalizes ASCII hostnames and reports a single trailing-dot change', () => {
    expect(normalizeHostnameInput('  WWW.Example.COM. ')).toEqual({ value: 'www.example.com', changed: true });
    expect(normalizeHostnameInput('www.example.com')).toEqual({ value: 'www.example.com', changed: false });
  });

  it.each(['', '/absolute.example.com', '*.example.com', '@', 'example..com', 'example.com..', '例子.example'])('rejects unsupported hostname input %s', (value) => {
    expect(() => normalizeHostnameInput(value)).toThrowError(ApiRequestError);
  });

  it.each([
    ['pending', '待处理'],
    ['verifying', '验证中'],
    ['certificate_pending', '证书处理中'],
    ['ready', '已就绪'],
    ['failed', '失败'],
  ] as const)('labels domain status %s', (status, label) => {
    expect(domainStatusLabel(status)).toBe(label);
  });

  it.each([
    ['pending', '待处理'],
    ['issuing', '签发中'],
    ['ready', '已就绪'],
    ['failed', '失败'],
  ] as const)('labels certificate status %s', (status, label) => {
    expect(certificateStatusLabel(status)).toBe(label);
  });

  it('delegates normalized configure, bind, verify and unbind actions to the adapter', async () => {
    const platform = { putPlatformDomainSettings: vi.fn().mockResolvedValue({}) };
    const domains = {
      bindApplicationCustomDomain: vi.fn().mockResolvedValue({}),
      verifyApplicationDomain: vi.fn().mockResolvedValue({}),
      unbindApplicationDomain: vi.fn().mockResolvedValue(undefined),
    };
    const client = { ...platform, ...domains };

    await configurePlatformDomain(client, ' Example.COM. ');
    await bindCustomDomain(client, 'app-1', ' WWW.Example.COM. ');
    await verifyDomain(client, 'app-1', 'domain-1');
    await unbindDomain(client, 'app-1', 'domain-1');

    expect(platform.putPlatformDomainSettings).toHaveBeenCalledWith({ baseDomain: 'example.com' }, undefined);
    expect(domains.bindApplicationCustomDomain).toHaveBeenCalledWith('app-1', { hostname: 'www.example.com' }, undefined);
    expect(domains.verifyApplicationDomain).toHaveBeenCalledWith('app-1', 'domain-1', undefined);
    expect(domains.unbindApplicationDomain).toHaveBeenCalledWith('app-1', 'domain-1', undefined);
  });

  it('copies the exact CNAME target without invoking a network client', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);

    await expect(copyCnameTarget('ingress.example.test', writeText)).resolves.toBe('ingress.example.test');
    expect(writeText).toHaveBeenCalledWith('ingress.example.test');
  });

  it('keeps fallback messaging when domain access fails', () => {
    const error = new ApiRequestError(503, '控制面暂时不可用，请稍后重试。', 'unavailable', 'dependency_unavailable');
    expect(domainManagementErrorMessage(error, 'fallback')).toBe('控制面暂时不可用，请稍后重试。');
    expect(domainManagementErrorMessage(new ApiRequestError(undefined, 'demo', 'unavailable', 'stub_unavailable'), 'fallback')).toContain('本地演示');
    expect(fallbackAccessNotice({
      runtimeReady: true,
      ipFallback: '198.51.100.20',
      platformAddress: null,
      customDomains: [],
      route: { desired: false, serving: false, routeId: null },
      certificate: { status: 'failed', subject: null, notAfter: null },
      serving: false,
    })).toContain('198.51.100.20');
  });

  it('summarizes server verification evidence without inventing readiness', () => {
    expect(verificationEvidenceSummary({ verification: {
      method: 'public_dns_read_only',
      status: 'verifying',
      name: '_open-card.example.com',
      value: 'proof',
      observedAt: '2026-08-28T00:00:00Z',
    } })).toContain('验证中');
  });
});
