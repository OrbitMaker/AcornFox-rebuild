import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { IconApps, IconBell, IconGlobe, IconHistogram, IconSetting } from '@douyinfe/semi-icons';
import { Avatar, Button, Spin } from '@douyinfe/semi-ui';
import type { ReactNode } from 'react';
import { createConfiguredApiClient } from './api/client';
import type { AIInterventionResult, AISettingsResult, ApplicationOperationsResult, ApplicationSummary, ApplicationUsageResult, ApiClient, OperationActor } from './api/types';
import { applyPublishingEvent, createPublishingSnapshot, type PublishEvent } from './domain/publishing';
import { ApplicationList } from './components/ApplicationList';
import { CreateApplicationWizard } from './components/CreateApplicationWizard';
import { ApplicationOperationsView } from './features/operations/ApplicationOperationsView';
import type { OperationRequest, OperationsViewMode } from './features/operations/operationsView';
import { AIInterventionPlaceholder } from './features/ai-interventions/AIInterventionPlaceholder';
import { UsageView } from './features/usage/UsageView';
import { AIInterventionPanel } from './features/ai-interventions/AIInterventionPanel';
import { AIServiceSettings } from './features/settings/ai/AIServiceSettings';

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

const webConsoleActor: OperationActor = { actor: 'web-console', role: 'operator' };

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

function Header({ view }: { view: View }) {
  const title = navItems.find((item) => item.id === view)?.label ?? '应用';
  return (
    <header className="topbar">
      <div className="topbar__breadcrumb"><span>Open Card</span><span className="breadcrumb-separator">/</span><strong>{view === 'create' ? '创建应用' : title}</strong></div>
      <div className="topbar__actions">
        <span className="instance-chip"><i /> 单机实例 · 本地控制面</span>
        <Button theme="borderless" icon={<IconBell />} aria-label="通知" />
        <Avatar color="light-green" size="small">OC</Avatar>
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

function PlaceholderView({ view, onCreate }: { view: View; onCreate: () => void }) {
  const item = navItems.find((navItem) => navItem.id === view) ?? navItems[0];
  return (
    <section className="page-section placeholder-page" aria-labelledby="placeholder-heading">
      <p className="eyebrow">{item.label}</p><h1 id="placeholder-heading">{item.label}</h1><p className="section-subtitle">{item.description}</p>
      <div className="placeholder-card"><div className="placeholder-icon">{item.icon}</div><h2>这个模块将接入控制面事实</h2><p>M0 只提供导航和边界。后续门禁会接入真实 API、事件、审计和证据，不在前端虚构状态。</p>{view === 'operations' && <Button theme="solid" type="primary" onClick={onCreate}>先创建一个应用</Button>}</div>
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
}

function OperationsWorkspace({ application, result, loading, message, mode, onModeChange, onRequestOperation, aiResult, aiLoading }: OperationsWorkspaceProps) {
  if (!application) {
    return <section className="page-section placeholder-page"><h1>运行与运维</h1><p>创建或接入应用后，才能读取该应用的控制面事实。</p><AIInterventionPlaceholder availability="disabled" /></section>;
  }
  if (loading) {
    return <section className="page-section placeholder-page"><h1>运行与运维</h1><Spin tip="正在读取控制面事实" /><AIInterventionPlaceholder availability="disabled" /></section>;
  }
  if (result?.status !== 'available') {
    return (
      <section className="page-section placeholder-page">
        <p className="eyebrow">运行与运维 · {application.name}</p><h1>运维事实未就绪</h1>
        <p>{message ?? result?.message ?? '控制面尚未提供该应用的运维事实。'}</p>
        <AIInterventionPlaceholder availability="disabled" />
      </section>
    );
  }
  return (
    <section className="page-section">
      {message && <div className="inline-alert" role="status">{message}</div>}
      <ApplicationOperationsView facts={result.facts} mode={mode} onModeChange={onModeChange} onRequestOperation={onRequestOperation} />
      {aiLoading ? <Spin tip="正在读取 AI 介入账本" /> : aiResult?.status === 'available' ? <AIInterventionPanel facts={aiResult.facts} mode={mode === 'operations' ? 'operator' : 'ordinary'} /> : <AIInterventionPlaceholder availability="disabled" />}
    </section>
  );
}

function AISettingsWorkspace({ result, loading }: { result?: AISettingsResult; loading: boolean }) {
  if (loading) return <section className="page-section placeholder-page"><h1>系统设置</h1><Spin tip="正在读取 AI 服务设置" /></section>;
  if (result?.status !== 'available') return <section className="page-section placeholder-page"><h1>AI 服务</h1><p>{result?.message ?? 'AI 服务设置未就绪。'}</p><AIInterventionPlaceholder availability="disabled" /></section>;
  return <section className="page-section"><AIServiceSettings settings={result.settings} /></section>;
}

function UsageWorkspace({ application, result, loading, mode, onModeChange }: { application?: ApplicationSummary; result?: ApplicationUsageResult; loading: boolean; mode: 'normal' | 'operations'; onModeChange: (mode: 'normal' | 'operations') => void }) {
  if (!application) return <section className="page-section placeholder-page"><h1>用量与分析</h1><p>创建或接入应用后，才能读取本地用量事实。</p></section>;
  if (loading) return <section className="page-section placeholder-page"><h1>用量与分析</h1><Spin tip="正在读取本地用量事实" /></section>;
  if (result?.status !== 'available') return <section className="page-section placeholder-page"><p className="eyebrow">用量与分析 · {application.name}</p><h1>用量事实未就绪</h1><p>{result?.message ?? '控制面尚未提供该应用的聚合用量事实。'}</p></section>;
  return <section className="page-section"><div className="usage-mode-switch" role="group" aria-label="用量视图"><Button theme={mode === 'normal' ? 'solid' : 'borderless'} onClick={() => onModeChange('normal')}>普通视图</Button><Button theme={mode === 'operations' ? 'solid' : 'borderless'} onClick={() => onModeChange('operations')}>运维视图</Button></div><UsageView facts={result.facts} mode={mode} /></section>;
}

export default function App() {
  const [client] = useState<ApiClient>(() => createConfiguredApiClient());
  const [view, setView] = useState<View>('overview');
  const [applications, setApplications] = useState<ApplicationSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string>();
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
  const subscriptions = useRef(new Map<string, () => void>());

  const loadApplications = useCallback(async () => {
    setLoading(true);
    setError(undefined);
    try {
      const response = await client.listApplications();
      setApplications(response.items);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : '应用列表加载失败');
    } finally {
      setLoading(false);
    }
  }, [client]);

  useEffect(() => {
    void loadApplications();
    return () => subscriptions.current.forEach((unsubscribe) => unsubscribe());
  }, [loadApplications]);

  const subscribe = useCallback((operationId: string) => {
    subscriptions.current.get(operationId)?.();
    const unsubscribe = client.subscribeToPublishEvents(operationId, (event) => setApplications((current) => updateFromPublishEvent(current, event)));
    subscriptions.current.set(operationId, unsubscribe);
  }, [client]);

  const handleCreated = useCallback((operationId: string) => {
    subscribe(operationId);
    setView('applications');
    void loadApplications();
  }, [loadApplications, subscribe]);

  const operationsApplication = applications[0];
  const loadOperations = useCallback(async () => {
    if (!operationsApplication) {
      setOperationsResult(undefined);
      return;
    }
    setOperationsLoading(true);
    setOperationsMessage(undefined);
    try {
      setOperationsResult(await client.getApplicationOperations(operationsApplication.id));
    } catch (reason) {
      setOperationsResult({ status: 'unavailable', message: reason instanceof Error ? reason.message : '运维事实加载失败' });
    } finally {
      setOperationsLoading(false);
    }
  }, [client, operationsApplication]);

  useEffect(() => {
    if (view === 'operations') void loadOperations();
  }, [loadOperations, view]);

  const loadAIInterventions = useCallback(async () => {
    if (!operationsApplication) { setAIResult(undefined); return; }
    setAILoading(true);
    try { setAIResult(await client.getAIInterventions(operationsApplication.id, operationsMode === 'operations' ? 'operator' : 'ordinary')); }
    catch (reason) { setAIResult({ status: 'unavailable', message: reason instanceof Error ? reason.message : 'AI 介入账本加载失败' }); }
    finally { setAILoading(false); }
  }, [client, operationsApplication, operationsMode]);

  useEffect(() => { if (view === 'operations') void loadAIInterventions(); }, [loadAIInterventions, view]);

  const loadAISettings = useCallback(async () => {
    setAISettingsLoading(true);
    try { setAISettingsResult(await client.getAISettings()); }
    catch (reason) { setAISettingsResult({ status: 'unavailable', message: reason instanceof Error ? reason.message : 'AI 服务设置加载失败' }); }
    finally { setAISettingsLoading(false); }
  }, [client]);

  useEffect(() => { if (view === 'settings') void loadAISettings(); }, [loadAISettings, view]);

  const loadUsage = useCallback(async () => {
    if (!operationsApplication) {
      setUsageResult(undefined);
      return;
    }
    setUsageLoading(true);
    try {
      setUsageResult(await client.getApplicationUsage(operationsApplication.id, usageMode));
    } catch (reason) {
      setUsageResult({ status: 'unavailable', message: reason instanceof Error ? reason.message : '用量事实加载失败' });
    } finally {
      setUsageLoading(false);
    }
  }, [client, operationsApplication, usageMode]);

  useEffect(() => {
    if (view === 'usage') void loadUsage();
  }, [loadUsage, view]);

  const requestOperation = useCallback((request: OperationRequest) => {
    if (!operationsApplication) return;
    setOperationsMessage(undefined);
    void client.requestApplicationOperation(operationsApplication.id, request, webConsoleActor)
      .then((result) => {
        setOperationsMessage(result.message);
        if (result.status === 'accepted') void loadOperations();
      })
      .catch((reason) => setOperationsMessage(reason instanceof Error ? reason.message : '运维操作请求失败'));
  }, [client, loadOperations, operationsApplication]);

  const stats = useMemo(() => ({ running: applications.filter((application) => application.runtimeStatus === 'running').length }), [applications]);

  return (
    <div className="app-shell">
      <Sidebar view={view} onNavigate={setView} />
      <div className="app-main">
        <Header view={view} />
        <main className="content">
          {view === 'overview' && <Overview applications={applications} onOpenApplications={() => setView('applications')} onCreate={() => setView('create')} />}
          {view === 'applications' && <ApplicationList applications={applications} loading={loading} error={error} onCreate={() => setView('create')} onRefresh={() => void loadApplications()} />}
          {view === 'create' && <CreateApplicationWizard client={client} onCancel={() => setView('applications')} onCreated={handleCreated} />}
          {view === 'operations' && <OperationsWorkspace application={operationsApplication} result={operationsResult} loading={operationsLoading} message={operationsMessage} mode={operationsMode} onModeChange={setOperationsMode} onRequestOperation={requestOperation} aiResult={aiResult} aiLoading={aiLoading} />}
          {view === 'usage' && <UsageWorkspace application={operationsApplication} result={usageResult} loading={usageLoading} mode={usageMode} onModeChange={setUsageMode} />}
          {view === 'settings' && <AISettingsWorkspace result={aiSettingsResult} loading={aiSettingsLoading} />}
          {view !== 'overview' && view !== 'applications' && view !== 'create' && view !== 'operations' && view !== 'usage' && view !== 'settings' && <PlaceholderView view={view} onCreate={() => setView('create')} />}
        </main>
        <footer className="app-footer"><span>Open Card MVP · Golden Path 在 AI 关闭时可独立运行</span><span>{loading ? <Spin size="small" /> : <><i className="footer-status" /> {stats.running} 个应用运行正常</>}</span></footer>
      </div>
    </div>
  );
}
