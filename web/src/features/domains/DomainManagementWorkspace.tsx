import { useCallback, useEffect, useRef, useState } from 'react';
import type { FormEvent } from 'react';
import { ApiRequestError } from '../../api/errors';
import type {
  ApiClient,
  ApplicationAccessResponse,
  ApplicationDomain,
  PlatformDomainSettingsResponse,
} from '../../api/types';
import {
  bindCustomDomain,
  certificateStatusLabel,
  configurePlatformDomain,
  copyCnameTarget,
  domainManagementErrorMessage,
  domainStatusLabel,
  fallbackAccessNotice,
  normalizeHostnameInput,
  UNBIND_OPERATION_FAILED_MESSAGE,
  unbindDomain,
  updateQueuedUnbindDomainIDs,
  verificationEvidenceSummary,
  verifyDomain,
} from './domainManagement';
import { createUnbindAttemptStore } from './unbindAttemptStore';
import './domainManagementWorkspace.css';

const unbindAttemptStore = createUnbindAttemptStore();

export interface DomainManagementWorkspaceProps {
  client: ApiClient;
  applicationId: string;
  onRefresh?: () => void;
  onError?: (error: unknown) => void;
}

export interface DomainManagementPanelProps {
  applicationId: string;
  platform?: PlatformDomainSettingsResponse | null;
  domains?: ApplicationDomain[] | null;
  access?: ApplicationAccessResponse | null;
  platformError?: unknown;
  domainsError?: unknown;
  accessError?: unknown;
  actionError?: unknown;
  loading: boolean;
  pendingAction?: string;
  queuedUnbindDomainIDs?: readonly string[];
  baseDomain: string;
  hostname: string;
  hostnameNotice?: string;
  copiedTarget?: string;
  onBaseDomainChange: (value: string) => void;
  onHostnameChange: (value: string) => void;
  onSavePlatform: (event: FormEvent<HTMLFormElement>) => void;
  onBindDomain: (event: FormEvent<HTMLFormElement>) => void;
  onRefresh: () => void;
  onRetryPlatform: () => void;
  onVerify: (domainId: string) => void;
  onUnbind: (domainId: string, hostname: string) => void;
  onCopyCname: (target: string) => void;
}

function statusClass(status: string): string {
  return `domain-management__status domain-management__status--${status}`;
}

function pending(action: string, pendingAction: string | undefined): boolean {
  return pendingAction === action;
}

function ErrorNotice({ error, fallback }: { error?: unknown; fallback: string }) {
  if (!error) return null;
  return <p className="domain-management__error" role="alert">{domainManagementErrorMessage(error, fallback)}</p>;
}

function LoadingNotice({ loading, label }: { loading: boolean; label: string }) {
  return loading ? <p className="domain-management__loading" role="status" aria-live="polite">{label}</p> : null;
}

export function DomainManagementPanel({
  applicationId,
  platform,
  domains,
  access,
  platformError,
  domainsError,
  accessError,
  actionError,
  loading,
  pendingAction,
  queuedUnbindDomainIDs = [],
  baseDomain,
  hostname,
  hostnameNotice,
  copiedTarget,
  onBaseDomainChange,
  onHostnameChange,
  onSavePlatform,
  onBindDomain,
  onRefresh,
  onRetryPlatform,
  onVerify,
  onUnbind,
  onCopyCname,
}: DomainManagementPanelProps) {
  const errorRef = useRef<HTMLParagraphElement>(null);
  const firstError = actionError ?? platformError ?? domainsError ?? accessError;

  useEffect(() => {
    if (firstError) errorRef.current?.focus();
  }, [firstError]);

  const accessNotice = fallbackAccessNotice(access, domains ?? []);

  return (
    <main className="domain-management" aria-labelledby="domain-management-heading">
      <header className="domain-management__header">
        <div>
          <p className="eyebrow">访问与域名</p>
          <h1 id="domain-management-heading">域名管理</h1>
          <p>配置由控制面记录和验证；本页面不会写入 DNS，也不会替代服务端最终验证。</p>
        </div>
        <button className="domain-management__refresh" type="button" onClick={onRefresh} disabled={loading || Boolean(pendingAction)}>
          {loading ? '正在刷新…' : '刷新状态'}
        </button>
      </header>

      {Boolean(firstError) && <p className="domain-management__error domain-management__error--global" ref={errorRef} role="alert" tabIndex={-1}>{domainManagementErrorMessage(firstError, '域名状态暂时不可用，请稍后重试。')}</p>}

      <section className="domain-management__card" aria-labelledby="platform-domain-heading">
        <header className="domain-management__card-header">
          <div>
            <p className="eyebrow">平台入口</p>
            <h2 id="platform-domain-heading">平台基础域名</h2>
          </div>
          <span className={statusClass(platform ? platform.status : platformError ? 'unavailable' : 'loading')}>
            {platform ? domainStatusLabel(platform.status) : platformError ? '不可用' : '加载中'}
          </span>
        </header>
        <LoadingNotice loading={platform === undefined} label="正在读取平台域名状态…" />
        <ErrorNotice error={platformError} fallback="平台域名状态暂时不可用。" />
        {platform && (
          <>
            <dl className="domain-management__facts">
              <div><dt>Base domain</dt><dd>{platform.baseDomain ?? '未配置'}</dd></div>
              <div><dt>Console domain</dt><dd>{platform.consoleDomain ?? '未生成'}</dd></div>
              <div><dt>应用地址规则</dt><dd>{platform.wildcardPattern ?? '*.apps.&lt;base_domain&gt;'}</dd></div>
              <div><dt>验证证据</dt><dd>{verificationEvidenceSummary(platform)}</dd></div>
              <div><dt>证书状态</dt><dd>{certificateStatusLabel(platform.certificate.status)}{platform.certificate.notAfter ? ` · 到期 ${platform.certificate.notAfter}` : ''}</dd></div>
              <div><dt>下一步</dt><dd>{platform.nextAction}</dd></div>
            </dl>
            <section className="domain-management__records" aria-labelledby="platform-dns-records-heading">
              <h3 id="platform-dns-records-heading">需发布的 DNS 记录</h3>
              {platform.dnsRecords.length === 0 ? <p className="domain-management__hint">配置平台基础域名后，服务端会列出 console、ingress 与应用通配记录。</p> : (
                <ul>
                  {platform.dnsRecords.map((record) => {
                    const copyValue = `${record.hostname} ${record.type} ${record.value}`;
                    return <li key={`${record.hostname}:${record.type}`}>
                      <code>{copyValue}</code>
                      <span>{record.purpose}</span>
                      <button type="button" onClick={() => onCopyCname(copyValue)} disabled={Boolean(pendingAction)}>{copiedTarget === copyValue ? '已复制' : '复制记录'}</button>
                    </li>;
                  })}
                </ul>
              )}
            </section>
            {platform.failure && <p className="domain-management__failure"><strong>失败：</strong>{platform.failure.message} ({platform.failure.code})</p>}
          </>
        )}
        <form className="domain-management__form" onSubmit={onSavePlatform} noValidate>
          <label htmlFor="platform-base-domain">平台基础域名</label>
          <input id="platform-base-domain" name="base-domain" value={baseDomain} onChange={(event) => onBaseDomainChange(event.target.value)} disabled={Boolean(pendingAction)} placeholder="example.com" autoComplete="off" />
          <p className="domain-management__hint">仅提交基础域名。平台应用地址使用服务端生成的 <code>*.apps</code> 规则；根域、A/ALIAS、CDN/WAF 不在此页面配置。</p>
          <button type="submit" disabled={!baseDomain.trim() || Boolean(pendingAction)}>{pending('platform-save', pendingAction) ? '正在保存…' : platform?.nextAction === 'retry' || platform?.status === 'failed' ? '重试平台域名' : '保存平台域名'}</button>
          {platform?.failure && <button className="domain-management__secondary" type="button" onClick={onRetryPlatform} disabled={!baseDomain.trim() || Boolean(pendingAction)}>再次验证</button>}
        </form>
      </section>

      <section className="domain-management__card" aria-labelledby="application-domains-heading">
        <header className="domain-management__card-header">
          <div>
            <p className="eyebrow">应用入口</p>
            <h2 id="application-domains-heading">应用域名</h2>
            <p className="domain-management__subtle">当前应用：<code>{applicationId}</code></p>
          </div>
        </header>
        <LoadingNotice loading={domains === undefined} label="正在读取应用域名…" />
        <ErrorNotice error={domainsError} fallback="应用域名状态暂时不可用。" />
        {domains && domains.length === 0 && <p className="domain-management__empty">当前没有已记录的应用域名。</p>}
        {domains && domains.length > 0 && (
          <div className="domain-management__domain-list">
            {domains.map((domain) => (
              <article className="domain-management__domain" key={domain.id}>
                <header>
                  <div>
                    <h3>{domain.hostname}</h3>
                    <p>{domain.kind === 'platform' ? '平台生成地址' : '客户 CNAME 地址'}</p>
                  </div>
                  <span className={statusClass(domain.status)}>{domainStatusLabel(domain.status)}</span>
                </header>
                <dl className="domain-management__facts">
                  <div><dt>CNAME 目标</dt><dd>{domain.cnameTarget ?? '服务端尚未提供'}</dd></div>
                  <div><dt>验证证据</dt><dd>{verificationEvidenceSummary(domain)}</dd></div>
                  <div><dt>证书</dt><dd>{certificateStatusLabel(domain.certificate.status)}</dd></div>
                  <div><dt>当前服务</dt><dd>{domain.serving ? '此域名正在服务' : '未切换服务'}</dd></div>
				  {domain.convergence && <div><dt>收敛状态</dt><dd>{domain.convergence.phase}{domain.convergence.lastError ? ` · ${domain.convergence.lastError}` : ''}</dd></div>}
                </dl>
                {domain.failure && <p className="domain-management__failure"><strong>失败：</strong>{domain.failure.message} ({domain.failure.code})</p>}
                <div className="domain-management__actions">
                  <button type="button" onClick={() => domain.cnameTarget && onCopyCname(domain.cnameTarget)} disabled={!domain.cnameTarget || Boolean(pendingAction)}>{copiedTarget === domain.cnameTarget ? '已复制' : '复制 CNAME'}</button>
				  <button type="button" onClick={() => onVerify(domain.id)} disabled={Boolean(pendingAction) || queuedUnbindDomainIDs.includes(domain.id)}>{pending(`verify:${domain.id}`, pendingAction) ? '正在验证…' : domain.status === 'failed' ? '重试验证' : '验证域名'}</button>
				  {domain.kind === 'custom' && <button className="domain-management__danger" type="button" onClick={() => onUnbind(domain.id, domain.hostname)} disabled={Boolean(pendingAction) || queuedUnbindDomainIDs.includes(domain.id)}>{pending(`unbind:${domain.id}`, pendingAction) || queuedUnbindDomainIDs.includes(domain.id) ? '正在解绑…' : '解绑'}</button>}
                </div>
                {domain.kind === 'custom' && <p className="domain-management__hint">{queuedUnbindDomainIDs.includes(domain.id) ? '解绑请求已记录，正在等待安全移除路由；IP fallback 和平台地址仍保留。' : '解绑不会影响 IP fallback 或平台地址。'}</p>}
              </article>
            ))}
          </div>
        )}
        <form className="domain-management__form" onSubmit={onBindDomain} noValidate>
          <label htmlFor="application-domain-hostname">绑定客户 hostname</label>
          <input id="application-domain-hostname" name="hostname" value={hostname} onChange={(event) => onHostnameChange(event.target.value)} disabled={Boolean(pendingAction)} placeholder="www.example.com" autoComplete="off" aria-describedby="application-domain-help" />
          <p id="application-domain-help" className="domain-management__hint">只填写客户 hostname。页面仅做 ASCII 小写和单个尾点提示，CNAME、证书和最终可用性由服务端验证。</p>
          {hostnameNotice && <p className="domain-management__notice" role="status">{hostnameNotice}</p>}
          <button type="submit" disabled={!hostname.trim() || Boolean(pendingAction)}>{pending('domain-bind', pendingAction) ? '正在绑定…' : '绑定域名'}</button>
        </form>
      </section>

      <section className="domain-management__card" aria-labelledby="access-state-heading">
        <header className="domain-management__card-header">
          <div>
            <p className="eyebrow">实际访问</p>
            <h2 id="access-state-heading">访问状态</h2>
          </div>
        </header>
        <LoadingNotice loading={access === undefined} label="正在读取访问状态…" />
        <ErrorNotice error={accessError} fallback="访问状态暂时不可用。" />
        {access && (
          <dl className="domain-management__facts domain-management__facts--access">
            <div><dt>应用运行</dt><dd>{access.runtimeReady ? '已就绪' : '未就绪'}</dd></div>
            <div><dt>IP fallback</dt><dd>{access.ipFallback ?? '不可用'}</dd></div>
            <div><dt>平台地址</dt><dd>{access.platformAddress?.hostname ?? '未生成'}</dd></div>
            <div><dt>路由</dt><dd>{access.route.serving ? '正在服务' : access.route.desired ? '目标已记录，尚未服务' : '未配置'}</dd></div>
            <div><dt>证书</dt><dd>{certificateStatusLabel(access.certificate.status)}</dd></div>
            <div><dt>当前服务</dt><dd>{access.serving ? '已服务' : '未服务'}</dd></div>
          </dl>
        )}
        {accessNotice && <p className="domain-management__fallback" role="status">{accessNotice}</p>}
      </section>
    </main>
  );
}

export function DomainManagementWorkspace({ client, applicationId, onRefresh, onError }: DomainManagementWorkspaceProps) {
  const [platform, setPlatform] = useState<PlatformDomainSettingsResponse | null | undefined>(undefined);
  const [domains, setDomains] = useState<ApplicationDomain[] | null | undefined>(undefined);
  const [access, setAccess] = useState<ApplicationAccessResponse | null | undefined>(undefined);
  const [platformError, setPlatformError] = useState<unknown>();
  const [domainsError, setDomainsError] = useState<unknown>();
  const [accessError, setAccessError] = useState<unknown>();
  const [actionError, setActionError] = useState<unknown>();
  const [loading, setLoading] = useState(false);
  const [pendingAction, setPendingAction] = useState<string>();
  const [baseDomain, setBaseDomain] = useState('');
  const [hostname, setHostname] = useState('');
  const [hostnameNotice, setHostnameNotice] = useState<string>();
  const [copiedTarget, setCopiedTarget] = useState<string>();
  const [queuedUnbindDomainIDs, setQueuedUnbindDomainIDs] = useState<ReadonlySet<string>>(() => new Set());
  const requestId = useRef(0);

  const reportError = useCallback((error: unknown) => {
    if (error instanceof DOMException && error.name === 'AbortError') return;
    onError?.(error);
  }, [onError]);

  const load = useCallback(async (signal?: AbortSignal) => {
    const currentRequest = ++requestId.current;
    setLoading(true);
    setPlatformError(undefined);
    setDomainsError(undefined);
    setAccessError(undefined);
    const results = await Promise.allSettled([
      client.getPlatformDomainSettings(signal),
      client.listApplicationDomains(applicationId, signal),
      client.getApplicationAccess(applicationId, signal),
    ]);
    if (currentRequest !== requestId.current) return;
    const [platformResult, domainsResult, accessResult] = results;
    if (platformResult.status === 'fulfilled') {
      setPlatform(platformResult.value);
      setBaseDomain(platformResult.value.baseDomain ?? '');
    } else {
      setPlatform(null);
      setPlatformError(platformResult.reason);
      reportError(platformResult.reason);
    }
    if (domainsResult.status === 'fulfilled') {
      setDomains(domainsResult.value.items);
	      setQueuedUnbindDomainIDs(new Set(domainsResult.value.items.filter((domain) => domain.convergence?.kind === 'unbind' && (domain.convergence.status === 'queued' || domain.convergence.status === 'leased' || domain.convergence.status === 'recovery_required')).map((domain) => domain.id)));
		  const active = new Set(domainsResult.value.items.filter((domain) => domain.convergence?.kind === 'unbind' && (domain.convergence.status === 'queued' || domain.convergence.status === 'leased' || domain.convergence.status === 'recovery_required')).map((domain) => domain.id));
		  unbindAttemptStore.reconcileApplication(applicationId, active);
    }
    else {
      setDomains(null);
      setDomainsError(domainsResult.reason);
      reportError(domainsResult.reason);
    }
    if (accessResult.status === 'fulfilled') setAccess(accessResult.value);
    else {
      setAccess(null);
      setAccessError(accessResult.reason);
      reportError(accessResult.reason);
    }
    setLoading(false);
  }, [applicationId, client, reportError]);

  useEffect(() => {
    const controller = new AbortController();
    void load(controller.signal);
    return () => controller.abort();
  }, [load]);

  const refresh = useCallback(() => {
    onRefresh?.();
    void load();
  }, [load, onRefresh]);

  const runAction = useCallback(async (action: string, operation: () => Promise<unknown>) => {
    setPendingAction(action);
    setActionError(undefined);
    try {
      await operation();
      await load();
    } catch (error) {
      setActionError(error);
      reportError(error);
    } finally {
      setPendingAction(undefined);
    }
  }, [load, reportError]);

  const handleSavePlatform = useCallback((event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    void runAction('platform-save', () => configurePlatformDomain(client, baseDomain));
  }, [baseDomain, client, runAction]);

  const handleBindDomain = useCallback((event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    void runAction('domain-bind', async () => {
      const result = await bindCustomDomain(client, applicationId, hostname);
      setHostname('');
      setHostnameNotice(undefined);
      return result;
    });
  }, [applicationId, client, hostname, runAction]);

  const handleHostnameChange = useCallback((value: string) => {
    setHostname(value);
    if (!value.trim()) {
      setHostnameNotice(undefined);
      return;
    }
    try {
      const normalized = normalizeHostnameInput(value);
      setHostnameNotice(normalized.changed ? `提交时将使用：${normalized.value}` : undefined);
    } catch {
      setHostnameNotice(undefined);
    }
  }, []);

  const handleVerify = useCallback((domainId: string) => {
    void runAction(`verify:${domainId}`, () => verifyDomain(client, applicationId, domainId));
  }, [applicationId, client, runAction]);

  const handleUnbind = useCallback((domainId: string, domainHostname: string) => {
    const confirmed = typeof window === 'undefined' || typeof window.confirm !== 'function'
      || window.confirm(`确认解绑 ${domainHostname}？解绑不会影响 IP fallback 或平台地址。`);
    if (!confirmed) return;
	void runAction(`unbind:${domainId}`, async () => {
		const idempotencyKey = unbindAttemptStore.getOrCreate(applicationId, domainId, () => `unbind:${domainId}:${typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function' ? crypto.randomUUID() : `${Date.now()}-${Math.random().toString(16).slice(2)}`}`);
		const operation = await unbindDomain(client, applicationId, domainId, idempotencyKey);
		setQueuedUnbindDomainIDs((current) => updateQueuedUnbindDomainIDs(current, operation.operation));
		if (operation.operation.status === 'failed') {
			unbindAttemptStore.clear(applicationId, domainId);
			await load();
			throw new ApiRequestError(409, UNBIND_OPERATION_FAILED_MESSAGE, 'conflict', 'unbind_failed');
		}
		if (operation.operation.status === 'completed') unbindAttemptStore.clear(applicationId, domainId);
		return operation;
	});
  }, [applicationId, client, load, runAction]);

  const handleCopyCname = useCallback((target: string) => {
    setPendingAction(`copy:${target}`);
    setActionError(undefined);
    void copyCnameTarget(target)
      .then(() => setCopiedTarget(target))
      .catch((error: unknown) => {
        setActionError(error);
        reportError(error);
      })
      .finally(() => setPendingAction(undefined));
  }, [reportError]);

  return <DomainManagementPanel
    applicationId={applicationId}
    platform={platform}
    domains={domains}
    access={access}
    platformError={platformError}
    domainsError={domainsError}
    accessError={accessError}
    actionError={actionError}
    loading={loading}
    pendingAction={pendingAction}
    queuedUnbindDomainIDs={[...queuedUnbindDomainIDs]}
    baseDomain={baseDomain}
    hostname={hostname}
    hostnameNotice={hostnameNotice}
    copiedTarget={copiedTarget}
    onBaseDomainChange={setBaseDomain}
    onHostnameChange={handleHostnameChange}
    onSavePlatform={handleSavePlatform}
    onBindDomain={handleBindDomain}
    onRefresh={refresh}
    onRetryPlatform={() => void runAction('platform-retry', () => configurePlatformDomain(client, baseDomain))}
    onVerify={handleVerify}
    onUnbind={handleUnbind}
    onCopyCname={handleCopyCname}
  />;
}
