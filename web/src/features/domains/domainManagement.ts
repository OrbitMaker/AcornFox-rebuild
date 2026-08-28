import { ApiRequestError } from '../../api/errors';
import type {
  ApiClient,
  ApplicationAccessResponse,
  ApplicationDomain,
  ApplicationDomainResponse,
  CustomDomainBindRequest,
  PlatformDomainSettingsRequest,
  PlatformDomainSettingsResponse,
} from '../../api/types';

export type DomainManagementClient = Pick<
  ApiClient,
  | 'getPlatformDomainSettings'
  | 'putPlatformDomainSettings'
  | 'listApplicationDomains'
  | 'bindApplicationCustomDomain'
  | 'verifyApplicationDomain'
  | 'unbindApplicationDomain'
  | 'getApplicationAccess'
>;

export interface NormalizedHostname {
  value: string;
  changed: boolean;
}

export function normalizeHostnameInput(raw: string): NormalizedHostname {
  const trimmed = raw.trim();
  const withoutOneTrailingDot = trimmed.endsWith('.') ? trimmed.slice(0, -1) : trimmed;
  const value = withoutOneTrailingDot.toLowerCase();
  if (
    !value
    || value.includes('..')
    || value.startsWith('.')
    || value.endsWith('.')
    || value.startsWith('*')
    || value === '@'
    || !/^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/.test(value)
  ) {
    throw new ApiRequestError(422, '请输入 ASCII 主机名；根域、通配符和 DNS 记录类型由服务端策略处理。', 'validation', 'invalid_hostname');
  }
  return { value, changed: value !== raw };
}

export function domainStatusLabel(status: ApplicationDomain['status'] | PlatformDomainSettingsResponse['status']): string {
  return {
    pending: '待处理',
    verifying: '验证中',
    certificate_pending: '证书处理中',
    ready: '已就绪',
    failed: '失败',
  }[status];
}

export function certificateStatusLabel(status: ApplicationDomain['certificate']['status']): string {
  return {
    pending: '待处理',
    issuing: '签发中',
    ready: '已就绪',
    failed: '失败',
  }[status];
}

export function verificationEvidenceSummary(domain: Pick<ApplicationDomain, 'verification'> | PlatformDomainSettingsResponse): string {
  const verification = 'verification' in domain ? domain.verification : undefined;
  if (!verification) return '暂无验证证据';
  const details = [verification.method, domainStatusLabel(verification.status)];
  if (verification.name) details.push(`名称 ${verification.name}`);
  if (verification.value) details.push(`值 ${verification.value}`);
  if (verification.observedAt) details.push(`观测于 ${verification.observedAt}`);
  return details.join(' · ');
}

export function domainManagementErrorMessage(error: unknown, fallback: string): string {
  if (error instanceof ApiRequestError) {
    if (error.code === 'stub_unavailable') return '本地演示模式不连接真实域名 API，未伪装为成功。';
    return error.message;
  }
  return fallback;
}

export function fallbackAccessNotice(
  access: ApplicationAccessResponse | null | undefined,
  domains: readonly ApplicationDomain[] = [],
): string | undefined {
  const failedDomain = domains.find((domain) => domain.status === 'failed' || domain.failure !== null);
  if (!failedDomain && !access?.ipFallback) return undefined;
  if (access?.ipFallback) return `域名或证书失败不会移除平台地址；IP fallback 仍可用：${access.ipFallback}。`;
  return '域名或证书失败不会改变应用运行状态；请修复失败原因后重试。';
}

export async function configurePlatformDomain(
  client: Pick<DomainManagementClient, 'putPlatformDomainSettings'>,
  rawBaseDomain: string,
  signal?: AbortSignal,
): Promise<PlatformDomainSettingsResponse> {
  const { value } = normalizeHostnameInput(rawBaseDomain);
  const input: PlatformDomainSettingsRequest = { baseDomain: value };
  return client.putPlatformDomainSettings(input, signal);
}

export async function bindCustomDomain(
  client: Pick<DomainManagementClient, 'bindApplicationCustomDomain'>,
  applicationId: string,
  rawHostname: string,
  signal?: AbortSignal,
): Promise<ApplicationDomainResponse> {
  const { value } = normalizeHostnameInput(rawHostname);
  const input: CustomDomainBindRequest = { hostname: value };
  return client.bindApplicationCustomDomain(applicationId, input, signal);
}

export function verifyDomain(
  client: Pick<DomainManagementClient, 'verifyApplicationDomain'>,
  applicationId: string,
  domainId: string,
  signal?: AbortSignal,
): Promise<ApplicationDomainResponse> {
  return client.verifyApplicationDomain(applicationId, domainId, signal);
}

export function unbindDomain(
  client: Pick<DomainManagementClient, 'unbindApplicationDomain'>,
  applicationId: string,
  domainId: string,
  signal?: AbortSignal,
): Promise<void> {
  return client.unbindApplicationDomain(applicationId, domainId, signal);
}

export async function copyCnameTarget(
  target: string,
  writeText?: (value: string) => Promise<void>,
): Promise<string> {
  const writer = writeText ?? (typeof navigator !== 'undefined' && navigator.clipboard ? navigator.clipboard.writeText.bind(navigator.clipboard) : undefined);
  if (!writer) throw new Error('当前浏览器不支持复制 CNAME。');
  await writer(target);
  return target;
}
