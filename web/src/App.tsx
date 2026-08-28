import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { IconApps, IconBell, IconGlobe, IconHistogram, IconSetting } from '@douyinfe/semi-icons';
import { Avatar, Button, Spin } from '@douyinfe/semi-ui';
import type { ReactNode } from 'react';
import { createConfiguredApiClient } from './api/client';
import type { AIInterventionResult, AISettingsResult, ApplicationDetail as ApplicationDetailFact, ApplicationOperationsResult, ApplicationSummary, ApplicationUsageResult, ApiClient } from './api/types';
import { applyPublishingEvent, createPublishingSnapshot, type PublishEvent } from './domain/publishing';
import { ApplicationList } from './components/ApplicationList';
import { ApplicationDetail } from './components/ApplicationDetail';
import { RequestState } from './components/RequestState';
import { CreateApplicationWizard } from './components/CreateApplicationWizard';
import { ApplicationOperationsView } from './features/operations/ApplicationOperationsView';
import type { OperationRequest, OperationsViewMode } from './features/operations/operationsView';
import { AIInterventionPlaceholder } from './features/ai-interventions/AIInterventionPlaceholder';
import { UsageView } from './features/usage/UsageView';
import { AIInterventionPanel } from './features/ai-interventions/AIInterventionPanel';
import { AIServiceSettings } from './features/settings/ai/AIServiceSettings';
import { LoginView } from './features/auth/LoginView';
import { PasswordRotation } from './features/auth/PasswordRotation';
import { authErrorMessage, type AuthSession } from './features/auth/auth';
import { DomainManagementWorkspace } from './features/domains/DomainManagementWorkspace';
import { SseConnectionStatus, type SseConnectionState } from './features/events/SseConnectionStatus';
import { applicationIdFromLocation, resolveSelectedApplicationId, setApplicationQuery } from './components/applicationSelection';

type View = 'overview' | 'applications' | 'create' | 'domains' | 'operations' | 'usage' | 'settings';

interface NavItem {
  id: View;
  label: string;
  icon: ReactNode;
  description: string;
}

const navItems: NavItem[] = [
  { id: 'overview', label: '总览', icon: <span className="nav-glyph">⌂</span>, description: '实例和应用概况' },
  { id: 'applications', label: '应用', icon: <IconApps />, description: '应用列表和创建向导' },
  { id: 'domains', label: '域名管理', icon: <IconGlobe />, description: '平台域名和应用域名' },
  { id: 'operations', label: '运行与运维', icon: <IconHistogram />, description: '状态、事件和通知' },
  { id: 'usage', label: '用量与分析', icon: <span className="nav-glyph">◒</span>, description: '资源观察和聚合' },
  { id: 'settings', label: '系统设置', icon: <IconSetting />, description: '节点和控制面设置' },
];

type AuthState =
  | { status: 'checking' }
  | { status: 'unauthenticated'; message?: string }
  | { status: 'authenticated'; session: AuthSession & { authenticated: true } };

function updateFromPublishEvent(applications: ApplicationSummary[], event: PublishEvent): ApplicationSummary[] {
  return applications.map((application) => {
    if (application.id !== event.applicationId && application.operationId !== event.operationId) return application;
    const publishing = applyPublishingEvent(application.publishing ?? createPublishingSnapshot(), event);
    return {
      ...application,
      publishing,
      updatedAt: event.occurredAt,
      runtimeStatus: event.status === 'succeeded' ? 'running' : application.runtimeStatus,
      runtimeReady: event.status === 'succeeded' ? true : application.runtimeReady,
    };
  });
}

function Header({ view, username, demoMode, onLogout }: { view: View; username?: string; demoMode: boolean; onLogout: () => void }) {
  const title = navItems.find((item) => item.id === view)?.label ?? '应用';
  return (
    <header className="topbar">
      <div className="topbar__breadcrumb"><span>Open Card</span><span className="breadcrumb-separator">/</span><strong>{view === 'create' ? '创建应用' : title}</strong></div>
      <div className="topbar__actions">
        <span className="instance-chip"><i /> {demoMode ? '本地演示模式' : '单机实例 · 本地控制面'}</span>
        <Button theme="borderless" icon={<IconBell />} aria-label="通知" />
        <span className="topbar-user">{username ?? '管理员'}</span>
        <Avatar color="light-green" size="small">OC</Avatar>
        <Button theme="borderless" onClick={onLogout}>退出登录</Button>
      </div>
    </header>
  );
}

function Sidebar({ view, onNavigate }: { view: View; onNavigate: (view: View) => void }) {
  return (
    <aside className="sidebar">
      <div className="brand-lockup"><span className="brand-mark">OC</span><span><strong>Open Card</strong><small>自部署应用控制台</small></span></div>
      <div className="sidebar-instance"><span className="sidebar-instance__dot" /><span><strong>当前实例</strong><small>预设单机 · 已连接</small></span></div>
      <nav className="main-nav" aria-label="主导航">
        <p className="nav-kicker">工作台</p>
        {navItems.slice(0, 2).map((item) => <NavButton item={item} active={view === item.id || (view === 'create' && item.id === 'applications')} onNavigate={onNavigate} key={item.id} />)}
        <p className="nav-kicker nav-kicker--spaced">运维</p>
        {navItems.slice(2, 5).map((item) => <NavButton item={item} active={view === item.id} onNavigate={onNavigate} key={item.id} />)}
        <p className="nav-kicker nav-kicker--spaced">实例</p>
        {navItems.slice(5).map((item) => <NavButton item={item} active={view === item.id} onNavigate={onNavigate} key={item.id} />)}
      </nav>
      <div className="sidebar-footer"><span className="footer-status" /><span><strong>控制面在线</strong><small>事件流已就绪</small></span></div>
    </aside>
  );
}

function NavButton({ item, active, onNavigate }: { item: NavItem; active: boolean; onNavigate: (view: View) => void }) {
  return <button className={`nav-button ${active ? 'is-active' : ''}`} type="button" onClick={() => onNavigate(item.id)} title={item.description}><span className="nav-button__icon">{item.icon}</span><span>{item.label}</span>{item.id === 'applications' && <span className="nav-count">M0</span>}</button>;
}

function Overview({ applications, onOpenApplications, onCreate }: { applications: ApplicationSummary[]; onOpenApplications: () => void; onCreate: () => void }) {
  const running = applications.filter((application) => application.runtimeStatus === 'running').length;
  const attention = applications.filter((application) => application.runtimeStatus === 'attention').length;
  const activePublishing = applications.filter((application) => application.publishing && !['succeeded', 'failed'].includes(application.publishing.status)).length;
  return (
    <section className="page-section overview-page" aria-labelledby="overview-heading">
      <header className="overview-hero">
        <div><p className="eyebrow">总览 · 本地实例</p><h1 id="overview-heading">把应用交付到自己的服务器。</h1><p>Open Card 控制面只管理当前实例的事实、发布和访问入口。</p></div>
        <div className="hero-signal"><span className="hero-signal__pulse" /><div><strong>控制面在线</strong><small>Docker / Node Agent 等待接入</small></div></div>
      </header>
      <div className="stat-grid">
        <div className="stat-card"><span>应用总数</span><strong>{applications.length}</strong><small>来源和发布定义由应用页管理</small></div>
        <div className="stat-card stat-card--green"><span>运行正常</span><strong>{running}</strong><small>状态来自运行观察，不替代发布状态</small></div>
        <div className="stat-card stat-card--amber"><span>需要关注</span><strong>{attention}</strong><small>域名和内部运行状态分开显示</small></div>
        <div className="stat-card stat-card--blue"><span>进行中的发布</span><strong>{activePublishing}</strong><small>真实事件推进，不显示虚假百分比</small></div>
      </div>
      <div className="overview-grid">
        <div className="overview-panel overview-panel--wide"><div className="panel-heading"><div><p className="eyebrow">下一步</p><h2>接入一个应用</h2></div><Button theme="solid" type="primary" onClick={onCreate}>创建应用</Button></div><p className="panel-copy">从 Git、文件夹或归档开始。创建后，控制面会先固化 SourceRevision，再由发布事件推进构建和部署。</p><div className="step-strip"><span><b>01</b>来源版本</span><span><b>02</b>交付定义</span><span><b>03</b>发布验证</span></div></div>
        <div className="overview-panel"><div className="panel-heading"><div><p className="eyebrow">快捷入口</p><h2>应用工作台</h2></div></div><p className="panel-copy">查看所有应用的发布、运行和访问事实。</p><Button theme="borderless" onClick={onOpenApplications}>打开应用列表 →</Button></div>
      </div>
    </section>
  );
}

interface OperationsWorkspaceProps {
  application?: ApplicationSummary;
  result?: ApplicationOperationsResult;
  loading: boolean;
  message?: string;
  mode: OperationsViewMode;
  onModeChange: (mode: OperationsViewMode) => void;
  onRequestOperation: (request: OperationRequest) => void;
  aiResult?: AIInterventionResult;
  aiLoading: boolean;
  sseState: SseConnectionState;
  sseLastEventId?: string;
}

function OperationsWorkspace({ application, result, loading, message, mode, onModeChange, onRequestOperation, aiResult, aiLoading, sseState, sseLastEventId }: OperationsWorkspaceProps) {
  if (!application) {
    return <section className="page-section placeholder-page"><h1>运行与运维</h1><RequestState message="请先从应用列表选择一个应用，才能读取该应用的控制面事实。" /><AIInterventionPlaceholder availability="disabled" /></section>;
  }
  if (loading) {
    return <section className="page-section placeholder-page"><h1>运行与运维</h1><RequestState loading /><AIInterventionPlaceholder availability="disabled" /></section>;
  }
  if (result?.status !== 'available') {
    return (
      <section className="page-section placeholder-page">
        <p className="eyebrow">运行与运维 · {application.name}</p><h1>运维事实未就绪</h1>
        <RequestState message={message ?? result?.message ?? '控制面尚未提供该应用的运维事实。'} />
        <AIInterventionPlaceholder availability="disabled" />
      </section>
    );
  }
  return (
    <section className="page-section">
      <SseConnectionStatus state={sseState} lastEventId={sseLastEventId} />
      {message && <div className="inline-alert" role="status">{message}</div>}
      <ApplicationOperationsView facts={result.facts} mode={mode} onModeChange={onModeChange} onRequestOperation={onRequestOperation} />
      {aiLoading ? <Spin tip="正在读取 AI 介入账本" /> : aiResult?.status === 'available' ? <AIInterventionPanel facts={aiResult.facts} mode={mode === 'operations' ? 'operator' : 'ordinary'} /> : <AIInterventionPlaceholder availability="disabled" />}
    </section>
  );
}

function AISettingsWorkspace({ result, loading, client, onSessionExpired }: { result?: AISettingsResult; loading: boolean; client: ApiClient; onSessionExpired: () => void }) {
  if (loading) return <section className="page-section placeholder-page"><h1>系统设置</h1><Spin tip="正在读取 AI 服务设置" /></section>;
  if (result?.status !== 'available') return <section className="page-section placeholder-page"><h1>AI 服务</h1><p>{result?.message ?? 'AI 服务设置未就绪。'}</p><AIInterventionPlaceholder availability="disabled" /></section>;
  return <section className="page-section"><AIServiceSettings settings={result.settings} /><PasswordRotation client={client} onCompleted={onSessionExpired} /></section>;
}

function UsageWorkspace({ application, result, loading, mode, onModeChange }: { application?: ApplicationSummary; result?: ApplicationUsageResult; loading: boolean; mode: 'normal' | 'operations'; onModeChange: (mode: 'normal' | 'operations') => void }) {
  if (!application) return <section className="page-section placeholder-page"><h1>用量与分析</h1><RequestState message="请先从应用列表选择一个应用，才能读取本地用量事实。" /></section>;
  if (loading) return <section className="page-section placeholder-page"><h1>用量与分析</h1><RequestState loading /></section>;
  if (result?.status !== 'available') return <section className="page-section placeholder-page"><p className="eyebrow">用量与分析 · {application.name}</p><h1>用量事实未就绪</h1><RequestState message={result?.message ?? '控制面尚未提供该应用的聚合用量事实。'} /></section>;
  return <section className="page-section"><div className="usage-mode-switch" role="group" aria-label="用量视图"><Button theme={mode === 'normal' ? 'solid' : 'borderless'} onClick={() => onModeChange('normal')}>普通视图</Button><Button theme={mode === 'operations' ? 'solid' : 'borderless'} onClick={() => onModeChange('operations')}>运维视图</Button></div><UsageView facts={result.facts} mode={mode} /></section>;
}

function isAbortError(reason: unknown): boolean {
  return reason instanceof DOMException && reason.name === 'AbortError';
}

export default function App() {
  const [authState, setAuthState] = useState<AuthState>({ status: 'checking' });
  const [view, setView] = useState<View>('overview');
  const [applications, setApplications] = useState<ApplicationSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<unknown>();
  const [selectedApplicationId, setSelectedApplicationId] = useState<string | undefined>(() => applicationIdFromLocation(typeof window === 'undefined' ? undefined : window.location));
  const [detail, setDetail] = useState<ApplicationDetailFact>();
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState<unknown>();
  const [detailReload, setDetailReload] = useState(0);
  const [operationsResult, setOperationsResult] = useState<ApplicationOperationsResult>();
  const [operationsLoading, setOperationsLoading] = useState(false);
  const [operationsMessage, setOperationsMessage] = useState<string>();
  const [operationsMode, setOperationsMode] = useState<OperationsViewMode>('normal');
  const [usageResult, setUsageResult] = useState<ApplicationUsageResult>();
  const [usageLoading, setUsageLoading] = useState(false);
  const [usageMode, setUsageMode] = useState<'normal' | 'operations'>('normal');
  const [aiResult, setAIResult] = useState<AIInterventionResult>();
  const [aiLoading, setAILoading] = useState(false);
  const [aiSettingsResult, setAISettingsResult] = useState<AISettingsResult>();
  const [aiSettingsLoading, setAISettingsLoading] = useState(false);
  const [sseState, setSseState] = useState<SseConnectionState>('closed');
  const [sseLastEventId, setSseLastEventId] = useState<string>();
  const subscriptions = useRef<(() => void) | undefined>();
  const requestControllers = useRef(new Set<AbortController>());
  const selectedApplicationIdRef = useRef<string>();
  selectedApplicationIdRef.current = selectedApplicationId;

  const trackController = useCallback(() => {
    const controller = new AbortController();
    requestControllers.current.add(controller);
    return controller;
  }, []);

  const cancelSelectedWork = useCallback(() => {
    requestControllers.current.forEach((controller) => controller.abort());
    requestControllers.current.clear();
    subscriptions.current?.();
    subscriptions.current = undefined;
    setSseLastEventId(undefined);
    setSseState('closed');
  }, []);

  const resetProtectedState = useCallback((message?: string) => {
    cancelSelectedWork();
    setApplications([]);
    setError(undefined);
    setSelectedApplicationId(undefined);
    setApplicationQuery(undefined);
    setDetail(undefined);
    setDetailError(undefined);
    setOperationsResult(undefined);
    setUsageResult(undefined);
    setAIResult(undefined);
    setAISettingsResult(undefined);
    setLoading(false);
    setDetailLoading(false);
    setOperationsLoading(false);
    setUsageLoading(false);
    setAILoading(false);
    setAISettingsLoading(false);
    setAuthState({ status: 'unauthenticated', message });
  }, [cancelSelectedWork]);

  const [client] = useState<ApiClient>(() => createConfiguredApiClient({ onUnauthorized: () => resetProtectedState('管理员会话已失效，请重新登录。') }));

  const loadApplications = useCallback(async (signal?: AbortSignal) => {
    setLoading(true);
    setError(undefined);
    try {
      const response = await client.listApplications(signal);
      setApplications(response.items);
      setSelectedApplicationId((current) => {
        const resolved = resolveSelectedApplicationId(current, response.items);
        if (current && !resolved) setApplicationQuery(undefined);
        return resolved;
      });
    } catch (reason) {
      if (!isAbortError(reason)) setError(reason);
    } finally {
      if (!signal?.aborted) setLoading(false);
    }
  }, [client]);

  useEffect(() => {
    const controller = trackController();
    void client.getSession(controller.signal)
      .then((session) => {
        if (controller.signal.aborted) return;
        if (session.authenticated) setAuthState({ status: 'authenticated', session });
        else setAuthState({ status: 'unauthenticated' });
      })
      .catch((reason) => {
        if (!controller.signal.aborted) setAuthState({ status: 'unauthenticated', message: authErrorMessage(reason, '无法验证管理员会话，请稍后重试。') });
      })
      .finally(() => requestControllers.current.delete(controller));
    return () => { controller.abort(); requestControllers.current.delete(controller); };
  }, [client, trackController]);

  useEffect(() => {
    if (authState.status !== 'authenticated') return undefined;
    const controller = trackController();
    void loadApplications(controller.signal).finally(() => requestControllers.current.delete(controller));
    return () => { controller.abort(); requestControllers.current.delete(controller); };
  }, [authState.status, loadApplications, trackController]);

  const selectedApplication = applications.find((application) => application.id === selectedApplicationId);

  const handleSelectApplication = useCallback((applicationId: string) => {
    if (applicationId === selectedApplicationIdRef.current) return;
    cancelSelectedWork();
    setSelectedApplicationId(applicationId);
    setApplicationQuery(applicationId);
    setDetail(undefined);
    setDetailError(undefined);
    setOperationsResult(undefined);
    setUsageResult(undefined);
    setAIResult(undefined);
    setOperationsMessage(undefined);
    setView('applications');
  }, [cancelSelectedWork]);

  const handleAuthenticated = useCallback((session: AuthSession) => {
    if (!session.authenticated) {
      setAuthState({ status: 'unauthenticated', message: '管理员会话未建立，请重试。' });
      return;
    }
    setAuthState({ status: 'authenticated', session });
    setView('overview');
  }, []);

  const handleLogout = useCallback(async () => {
    try {
      await client.logout();
    } catch {
      // Local state is cleared even if the remote logout response is unavailable.
    } finally {
      resetProtectedState('已退出管理员会话。');
    }
  }, [client, resetProtectedState]);

  const handlePasswordRotated = useCallback(() => {
    resetProtectedState('密码已更新，请使用新密码重新登录。');
  }, [resetProtectedState]);

  const handleCreated = useCallback((_operationId: string) => {
    setView('applications');
    void loadApplications();
  }, [loadApplications]);

  useEffect(() => {
    if (!selectedApplicationId || !selectedApplication) {
      setDetail(undefined);
      setDetailError(undefined);
      setDetailLoading(false);
      return undefined;
    }
    const applicationId = selectedApplicationId;
    const controller = trackController();
    setDetail(undefined);
    setDetailError(undefined);
    setDetailLoading(true);
    void client.getApplication(applicationId, controller.signal)
      .then((result) => { if (selectedApplicationIdRef.current === applicationId) setDetail(result); })
      .catch((reason) => { if (!controller.signal.aborted && selectedApplicationIdRef.current === applicationId) setDetailError(reason); })
      .finally(() => {
        requestControllers.current.delete(controller);
        if (!controller.signal.aborted && selectedApplicationIdRef.current === applicationId) setDetailLoading(false);
      });
    return () => { controller.abort(); requestControllers.current.delete(controller); };
  }, [client, detailReload, selectedApplication?.id, selectedApplicationId, trackController]);

  const loadOperations = useCallback(async (applicationId: string, signal?: AbortSignal) => {
    setOperationsLoading(true);
    setOperationsMessage(undefined);
    try {
      const result = await client.getApplicationOperations(applicationId, signal);
      if (selectedApplicationIdRef.current === applicationId) setOperationsResult(result);
    } catch (reason) {
      if (!isAbortError(reason) && selectedApplicationIdRef.current === applicationId) setOperationsResult({ status: 'unavailable', message: reason instanceof Error ? reason.message : '运维事实加载失败' });
    } finally {
      if (!signal?.aborted && selectedApplicationIdRef.current === applicationId) setOperationsLoading(false);
    }
  }, [client]);

  useEffect(() => {
    if (view !== 'operations' || !selectedApplicationId || !selectedApplication) {
      setOperationsResult(undefined);
      setOperationsLoading(false);
      return undefined;
    }
    const controller = trackController();
    void loadOperations(selectedApplicationId, controller.signal).finally(() => requestControllers.current.delete(controller));
    return () => { controller.abort(); requestControllers.current.delete(controller); };
  }, [loadOperations, selectedApplication?.id, selectedApplicationId, trackController, view]);

  const loadAIInterventions = useCallback(async (applicationId: string, mode: 'ordinary' | 'operator', signal?: AbortSignal) => {
    setAILoading(true);
    try {
      const result = await client.getAIInterventions(applicationId, mode, signal);
      if (selectedApplicationIdRef.current === applicationId) setAIResult(result);
    } catch (reason) {
      if (!isAbortError(reason) && selectedApplicationIdRef.current === applicationId) setAIResult({ status: 'unavailable', message: reason instanceof Error ? reason.message : 'AI 介入账本加载失败' });
    } finally {
      if (!signal?.aborted && selectedApplicationIdRef.current === applicationId) setAILoading(false);
    }
  }, [client]);

  useEffect(() => {
    if (view !== 'operations' || !selectedApplicationId || !selectedApplication) {
      setAIResult(undefined);
      setAILoading(false);
      return undefined;
    }
    const controller = trackController();
    void loadAIInterventions(selectedApplicationId, operationsMode === 'operations' ? 'operator' : 'ordinary', controller.signal).finally(() => requestControllers.current.delete(controller));
    return () => { controller.abort(); requestControllers.current.delete(controller); };
  }, [loadAIInterventions, operationsMode, selectedApplication?.id, selectedApplicationId, trackController, view]);

  const loadAISettings = useCallback(async (signal?: AbortSignal) => {
    setAISettingsLoading(true);
    try { setAISettingsResult(await client.getAISettings(signal)); }
    catch (reason) { if (!isAbortError(reason)) setAISettingsResult({ status: 'unavailable', message: reason instanceof Error ? reason.message : 'AI 服务设置加载失败' }); }
    finally { if (!signal?.aborted) setAISettingsLoading(false); }
  }, [client]);

  useEffect(() => {
    if (view !== 'settings') return undefined;
    const controller = trackController();
    void loadAISettings(controller.signal).finally(() => requestControllers.current.delete(controller));
    return () => { controller.abort(); requestControllers.current.delete(controller); };
  }, [loadAISettings, trackController, view]);

  const loadUsage = useCallback(async (applicationId: string, mode: 'normal' | 'operations', signal?: AbortSignal) => {
    setUsageLoading(true);
    try {
      const result = await client.getApplicationUsage(applicationId, mode, signal);
      if (selectedApplicationIdRef.current === applicationId) setUsageResult(result);
    } catch (reason) {
      if (!isAbortError(reason) && selectedApplicationIdRef.current === applicationId) setUsageResult({ status: 'unavailable', message: reason instanceof Error ? reason.message : '用量事实加载失败' });
    } finally {
      if (!signal?.aborted && selectedApplicationIdRef.current === applicationId) setUsageLoading(false);
    }
  }, [client]);

  useEffect(() => {
    if (view !== 'usage' || !selectedApplicationId || !selectedApplication) {
      setUsageResult(undefined);
      setUsageLoading(false);
      return undefined;
    }
    const controller = trackController();
    void loadUsage(selectedApplicationId, usageMode, controller.signal).finally(() => requestControllers.current.delete(controller));
    return () => { controller.abort(); requestControllers.current.delete(controller); };
  }, [loadUsage, selectedApplication?.id, selectedApplicationId, trackController, usageMode, view]);

  useEffect(() => {
    subscriptions.current?.();
    subscriptions.current = undefined;
    setSseLastEventId(undefined);
    if (!selectedApplication?.operationId) {
      setSseState('closed');
      return undefined;
    }
    const applicationId = selectedApplication.id;
    const operationId = selectedApplication.operationId;
    setSseState('connecting');
    try {
      const unsubscribe = client.subscribeToPublishEvents(operationId, (event) => {
        if (selectedApplicationIdRef.current !== applicationId) return;
        setSseState('connected');
        setSseLastEventId(event.id);
        setApplications((current) => updateFromPublishEvent(current, event));
      });
      subscriptions.current = unsubscribe;
      setSseState('connected');
      return () => {
        unsubscribe();
        if (subscriptions.current === unsubscribe) subscriptions.current = undefined;
        setSseState('closed');
      };
    } catch {
      setSseState('offline');
      return undefined;
    }
  }, [client, selectedApplication?.id, selectedApplication?.operationId]);

  const requestOperation = useCallback((request: OperationRequest) => {
    const applicationId = selectedApplicationIdRef.current;
    if (!applicationId) return;
    const controller = trackController();
    setOperationsMessage(undefined);
    void client.requestApplicationOperation(applicationId, request, controller.signal)
      .then((result) => {
        if (selectedApplicationIdRef.current !== applicationId) return;
        setOperationsMessage(result.message);
        if (result.status === 'accepted') void loadOperations(applicationId);
      })
      .catch((reason) => { if (!isAbortError(reason) && selectedApplicationIdRef.current === applicationId) setOperationsMessage(reason instanceof Error ? reason.message : '运维操作请求失败'); })
      .finally(() => requestControllers.current.delete(controller));
  }, [client, loadOperations, trackController]);

  const refreshDetail = useCallback(() => setDetailReload((value) => value + 1), []);
  const handleDomainError = useCallback((reason: unknown) => setError(reason), []);
  const stats = useMemo(() => ({ running: applications.filter((application) => application.runtimeStatus === 'running').length }), [applications]);

  if (authState.status === 'checking') {
    return <main className="auth-shell auth-shell--checking"><section className="auth-card"><span className="brand-mark">OC</span><h1>正在验证管理员会话</h1><Spin tip="请稍候" /></section></main>;
  }
  if (authState.status === 'unauthenticated') {
    return <LoginView client={client} message={authState.message} onAuthenticated={handleAuthenticated} />;
  }

  return (
    <div className="app-shell">
      <Sidebar view={view} onNavigate={setView} />
      <div className="app-main">
        <Header view={view} username={authState.session.username} demoMode={client.authMode === 'stub'} onLogout={() => void handleLogout()} />
        <main className="content">
          {view === 'overview' && <Overview applications={applications} onOpenApplications={() => setView('applications')} onCreate={() => setView('create')} />}
          {view === 'applications' && <><ApplicationList applications={applications} loading={loading} error={error} selectedApplicationId={selectedApplicationId} onSelect={handleSelectApplication} onCreate={() => setView('create')} onRefresh={() => void loadApplications()} /><ApplicationDetail application={selectedApplication} detail={detail} loading={detailLoading} error={detailError} onRefresh={refreshDetail} /></>}
          {view === 'create' && <CreateApplicationWizard client={client} onCancel={() => setView('applications')} onCreated={handleCreated} />}
          {view === 'domains' && (selectedApplication ? <DomainManagementWorkspace client={client} applicationId={selectedApplication.id} onRefresh={() => void loadApplications()} onError={handleDomainError} /> : <section className="page-section placeholder-page"><h1>域名管理</h1><RequestState message="请先从应用列表选择一个应用，才能管理其平台和应用域名。" /></section>)}
          {view === 'operations' && <OperationsWorkspace application={selectedApplication} result={operationsResult} loading={operationsLoading} message={operationsMessage} mode={operationsMode} onModeChange={setOperationsMode} onRequestOperation={requestOperation} aiResult={aiResult} aiLoading={aiLoading} sseState={sseState} sseLastEventId={sseLastEventId} />}
          {view === 'usage' && <UsageWorkspace application={selectedApplication} result={usageResult} loading={usageLoading} mode={usageMode} onModeChange={setUsageMode} />}
          {view === 'settings' && <AISettingsWorkspace result={aiSettingsResult} loading={aiSettingsLoading} client={client} onSessionExpired={handlePasswordRotated} />}
        </main>
        <footer className="app-footer"><span>Open Card MVP · Golden Path 在 AI 关闭时可独立运行</span><span>{loading ? <Spin size="small" /> : <><i className="footer-status" /> {stats.running} 个应用运行正常</>}</span></footer>
      </div>
    </div>
  );
}
