import { renderToStaticMarkup } from 'react-dom/server';
import { DomainAccessStatus } from './DomainAccessStatus';
import {
  domainAccessStatuses,
  projectDomainAccess,
  type DomainAccessSnapshot,
} from './domainAccess';

const running = (overrides: Partial<DomainAccessSnapshot> = {}): DomainAccessSnapshot => ({
  application: 'running',
  ipFallback: 'not_ready',
  domainVerification: 'not_configured',
  https: 'not_requested',
  trafficSwitch: 'not_switching',
  ...overrides,
});

describe('M3 domain access projection', () => {
  it('keeps application health distinct from an unready address', () => {
    const snapshot = running();

    expect(projectDomainAccess(snapshot)).toEqual({
      application: 'application_running',
      address: 'address_not_ready',
    });
    expect(domainAccessStatuses(snapshot)).toEqual(['application_running', 'address_not_ready']);
  });

  it('reports IP fallback without claiming a domain or HTTPS', () => {
    expect(projectDomainAccess(running({ ipFallback: 'available' }))).toEqual({
      application: 'application_running',
      address: 'ip_available',
    });
  });

  it('reports verification before certificate readiness', () => {
    expect(projectDomainAccess(running({
      ipFallback: 'available',
      domainVerification: 'verifying',
      https: 'ready',
    }))).toEqual({
      application: 'application_running',
      address: 'domain_verifying',
    });
  });

  it('only reports HTTPS ready for a verified domain and ready certificate', () => {
    expect(projectDomainAccess(running({
      domainVerification: 'verified',
      https: 'ready',
    }))).toEqual({
      application: 'application_running',
      address: 'https_ready',
    });
    expect(projectDomainAccess(running({ https: 'ready' })).address).toBe('address_not_ready');
  });

  it('prioritizes a failed traffic switch while preserving the running fact', () => {
    expect(projectDomainAccess(running({
      ipFallback: 'available',
      domainVerification: 'verified',
      https: 'ready',
      trafficSwitch: 'failed_old_version_serving',
    }))).toEqual({
      application: 'application_running',
      address: 'switch_failed_old_version_serving',
    });
  });

  it('renders discrete facts and never a made-up percentage', () => {
    const markup = renderToStaticMarkup(<DomainAccessStatus snapshot={running({ ipFallback: 'available' })} />);

    expect(markup).toContain('应用已运行');
    expect(markup).toContain('IP 可用');
    expect(markup).toContain('域名或 HTTPS 已就绪');
    expect(markup).not.toMatch(/\d+%/);
  });
});
