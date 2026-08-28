/**
 * Domain and route information is an observation of the control plane, not a
 * release result. In particular, a running application does not imply that a
 * hostname or a certificate is ready.
 */
export type ApplicationRunState = 'running' | 'not_running' | 'unknown';

export type IPFallbackState = 'available' | 'not_ready' | 'unknown';

export type DomainVerificationState = 'not_configured' | 'verifying' | 'verified' | 'failed';

export type HTTPSState = 'not_requested' | 'provisioning' | 'ready' | 'failed';

export type TrafficSwitchState = 'not_switching' | 'switching' | 'serving_current' | 'failed_old_version_serving';

export interface DomainAccessSnapshot {
  application: ApplicationRunState;
  ipFallback: IPFallbackState;
  domainVerification: DomainVerificationState;
  https: HTTPSState;
  trafficSwitch: TrafficSwitchState;
}

/** The six product-visible facts required for M3. None represents progress. */
export type DomainAccessStatus =
  | 'application_running'
  | 'address_not_ready'
  | 'ip_available'
  | 'domain_verifying'
  | 'https_ready'
  | 'switch_failed_old_version_serving';

export interface DomainAccessStatusDefinition {
  label: string;
  detail: string;
  tone: 'neutral' | 'info' | 'success' | 'warning' | 'danger';
}

export const DOMAIN_ACCESS_STATUS_DEFINITIONS: Record<DomainAccessStatus, DomainAccessStatusDefinition> = {
  application_running: {
    label: '应用已运行',
    detail: '运行健康独立于地址、域名和证书状态。',
    tone: 'success',
  },
  address_not_ready: {
    label: '地址未就绪',
    detail: '尚无已确认的访问入口；不会显示临时域名或 HTTPS。',
    tone: 'neutral',
  },
  ip_available: {
    label: 'IP 可用',
    detail: '可通过 IP 与系统分配端口访问；这不表示域名或 HTTPS 已就绪。',
    tone: 'info',
  },
  domain_verifying: {
    label: '域名验证中',
    detail: '域名路由尚未启用，IP fallback 继续可用。',
    tone: 'warning',
  },
  https_ready: {
    label: 'HTTPS 就绪',
    detail: '域名已验证且证书可用。',
    tone: 'success',
  },
  switch_failed_old_version_serving: {
    label: '切流失败，旧版服务中',
    detail: '新版本没有接管流量；旧版与 IP fallback 保持可用。',
    tone: 'danger',
  },
};

export interface DomainAccessProjection {
  application: DomainAccessStatus | undefined;
  address: DomainAccessStatus;
}

/**
 * Projects the two independent user-facing state axes. A switch failure has
 * priority over a successful domain/certificate observation because it tells
 * the user which version is actually serving traffic.
 */
export function projectDomainAccess(snapshot: DomainAccessSnapshot): DomainAccessProjection {
  const application = snapshot.application === 'running' ? 'application_running' : undefined;

  if (snapshot.trafficSwitch === 'failed_old_version_serving') {
    return { application, address: 'switch_failed_old_version_serving' };
  }
  if (snapshot.domainVerification === 'verifying') {
    return { application, address: 'domain_verifying' };
  }
  if (snapshot.domainVerification === 'verified' && snapshot.https === 'ready') {
    return { application, address: 'https_ready' };
  }
  if (snapshot.ipFallback === 'available') {
    return { application, address: 'ip_available' };
  }
  return { application, address: 'address_not_ready' };
}

/** Returns status facts in display order without fabricating a completion rate. */
export function domainAccessStatuses(snapshot: DomainAccessSnapshot): readonly DomainAccessStatus[] {
  const projection = projectDomainAccess(snapshot);
  return projection.application === undefined
    ? [projection.address]
    : [projection.application, projection.address];
}

export function domainAccessStatusDefinition(status: DomainAccessStatus): DomainAccessStatusDefinition {
  return DOMAIN_ACCESS_STATUS_DEFINITIONS[status];
}
