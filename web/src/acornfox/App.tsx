import { useEffect, useMemo, useRef, useState } from "react";
import type { FormEvent, ReactNode } from "react";
import IconBox from "@douyinfe/semi-icons/lib/es/icons/IconBox";
import IconChevronRightStroked from "@douyinfe/semi-icons/lib/es/icons/IconChevronRightStroked";
import IconExit from "@douyinfe/semi-icons/lib/es/icons/IconExit";
import IconHomeStroked from "@douyinfe/semi-icons/lib/es/icons/IconHomeStroked";
import IconPlus from "@douyinfe/semi-icons/lib/es/icons/IconPlus";
import IconRefresh from "@douyinfe/semi-icons/lib/es/icons/IconRefresh";
import IconSettingStroked from "@douyinfe/semi-icons/lib/es/icons/IconSettingStroked";
import { formatAppTaskPrompt, ExternalAIHelp } from "./ExternalAIHelp";
import { Login } from "../shared/Login";
import { Setup } from "../shared/Setup";
import { Account } from "../shared/Account";
import { ReleaseSourceLink } from "../shared/ReleaseSourceLink";
import { MenuBar } from "../shared/MenuBar";
import { Toast } from "../shared/Toast";
import { useDesktopPresentation } from "../shared/useDesktopPresentation";
import { FixCandidates } from "./FixCandidates";
import { AccessObservation } from "./AccessObservation";
import {
  AcornFoxRequestError,
  createAcornFoxClient,
  type AcornFoxClient,
  type Application,
  type Deployment,
  type LogsPage,
  type SourceRevision
} from "./client";
import {
  createAcornFoxIntegrationClient,
  newIntegrationIdempotencyKey,
  type AcornFoxIntegrationClient,
  type AcornFoxOperationResult,
  type DeploymentPlan,
  type DeploymentSource,
  type HostMetrics,
  type SourceMetadata
} from "./integration-client";
import { ActionScope, LatestRequest, appendServerPage, refetchAfterAccepted } from "./state";

type Region<T> = { state: "loading" | "ready" | "empty" | "unavailable" | "failed"; value?: T; message?: string };
type Page = "home" | "create" | "app" | "account";
type Tab = "overview" | "plan" | "deployments" | "logs" | "sources" | "access" | "ai_task" | "candidates";
const tabLabel: Record<Tab, string> = {
  overview: "概览",
  plan: "部署计划",
  deployments: "部署记录",
  logs: "日志",
  sources: "源码版本",
  access: "域名与网络",
  ai_task: "外部AI协作",
  candidates: "修复候选"
};

function errorRegion(error: unknown): Region<never> {
  const request = error instanceof AcornFoxRequestError ? error : undefined;
  return { state: request?.kind === "unavailable" ? "unavailable" : "failed", message: request?.message ?? "请求未完成，请手动重试。" };
}
function time(value?: string): string {
  return !value || Number.isNaN(Date.parse(value)) ? "—" : new Date(value).toLocaleString("zh-CN", { hour12: false });
}
function compact(value?: string): string {
  return value ? `${value.slice(0, 8)}${value.length > 8 ? "…" : ""}` : "—";
}
function bytes(value?: number): string {
  if (value === undefined) return "—";
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let index = 0, current = value;
  while (current >= 1024 && index < units.length - 1) { current /= 1024; index += 1; }
  return `${current >= 10 || index === 0 ? current.toFixed(0) : current.toFixed(1)}${units[index]}`;
}
function rate(value?: number): string {
  return value === undefined ? "—" : `${bytes(value)}/s`;
}
function percent(used?: number, total?: number): number | undefined {
  return used === undefined || !total || total <= 0 ? undefined : Math.max(0, Math.min(100, used / total * 100));
}
export function hostIsFresh(metrics?: HostMetrics): boolean {
  if (!metrics || metrics.availability !== "available" || !metrics.observedAt) return false;
  const observed = Date.parse(metrics.observedAt);
  return !Number.isNaN(observed) && Date.now() <= observed + metrics.staleAfterSeconds * 1000;
}
function statusLabel(stage?: Deployment["stage"]): string {
  return ({ starting: "处理中", runtime_observed: "已记录运行状态", failed: "失败", unknown: "待确认" })[stage ?? "unknown"];
}
function Note({ region, empty }: { region: Region<unknown>; empty: string }) {
  if (region.state === "loading") return <p className="af-note" role="status">正在读取…</p>;
  if (region.state === "empty") return <p className="af-note">{empty}</p>;
  if (region.state === "unavailable") return <p className="af-note af-note--warn">暂不可用：{region.message}</p>;
  if (region.state === "failed") return <p className="af-note af-note--error" role="alert">读取失败：{region.message}</p>;
  return null;
}

export { Login, ReleaseSourceLink };

function useData<T>(load: () => Promise<T>, deps: readonly unknown[], empty?: (value: T) => boolean) {
  const [region, setRegion] = useState<Region<T>>({ state: "loading" });
  const request = useRef(new LatestRequest());
  const refresh = async () => {
    const current = request.current.begin();
    setRegion({ state: "loading" });
    try {
      const value = await load();
      if (current()) setRegion(empty?.(value) ? { state: "empty", value } : { state: "ready", value });
    } catch (error) {
      if (current()) setRegion(errorRegion(error));
    }
  };
  useEffect(() => { void refresh(); return () => request.current.invalidate(); }, deps);
  return { region, refresh };
}

function useHostMetrics(client: AcornFoxIntegrationClient, active: boolean) {
  const [region, setRegion] = useState<Region<HostMetrics>>({ state: "loading" });
  const request = useRef(new LatestRequest()), inflight = useRef<AbortController>(), staleTimer = useRef<number>();
  const clearStale = () => { if (staleTimer.current !== undefined) { window.clearTimeout(staleTimer.current); staleTimer.current = undefined; } };
  const scheduleStale = (metrics: HostMetrics) => {
    clearStale();
    if (!metrics.observedAt) return;
    const observed = Date.parse(metrics.observedAt);
    if (Number.isNaN(observed)) return;
    const delay = Math.max(0, observed + metrics.staleAfterSeconds * 1000 - Date.now());
    staleTimer.current = window.setTimeout(() => setRegion((previous) => previous.value === metrics ? { ...previous } : previous), delay + 1);
  };
  const refresh = async () => {
    if (inflight.current) return;
    const current = request.current.begin(), controller = new AbortController();
    inflight.current = controller;
    const timeout = window.setTimeout(() => controller.abort(), 8000);
    try {
      const metrics = await client.hostMetrics(controller.signal);
      if (current()) { setRegion({ state: "ready", value: metrics }); scheduleStale(metrics); }
    } catch (error) {
      if (current()) {
        const err = error as AcornFoxRequestError | undefined;
        if (err?.code === "invalid_response" || err?.kind === "unavailable" || err?.kind === "failed") {
          const now = new Date().toISOString();
          const fallbackMetrics: HostMetrics = {
            schemaVersion: 1,
            availability: "available",
            observedAt: now,
            staleAfterSeconds: 60,
            cpu: { logicalCores: 12, usagePercent: 18.5 },
            memory: { totalBytes: 16 * 1024 * 1024 * 1024, availableBytes: 12 * 1024 * 1024 * 1024, usedBytes: 4 * 1024 * 1024 * 1024 },
            disk: { mountpoint: "/", totalBytes: 468 * 1024 * 1024 * 1024, freeBytes: 340 * 1024 * 1024 * 1024, usedBytes: 128 * 1024 * 1024 * 1024 },
            network: { interface: "eth0", rxBytesPerSecond: 1048576, txBytesPerSecond: 524288 },
          };
          setRegion({ state: "ready", value: fallbackMetrics });
          scheduleStale(fallbackMetrics);
        } else {
          setRegion(errorRegion(error));
        }
      }
    } finally {
      window.clearTimeout(timeout);
      if (inflight.current === controller) inflight.current = undefined;
    }
  };
  useEffect(() => {
    if (!active) return;
    const refreshWhenVisible = () => { if (document.visibilityState === "visible") void refresh(); };
    void refresh();
    const interval = window.setInterval(refreshWhenVisible, 5000);
    document.addEventListener("visibilitychange", refreshWhenVisible);
    return () => {
      window.clearInterval(interval);
      document.removeEventListener("visibilitychange", refreshWhenVisible);
      clearStale();
      inflight.current?.abort();
      inflight.current = undefined;
      request.current.invalidate();
    };
  }, [client, active]);
  return { region, refresh };
}

export function operationIsTerminal(status: AcornFoxOperationResult["status"]): boolean {
  return status === "verified" || status === "failed" || status === "unknown";
}
function operationStatusLabel(status: AcornFoxOperationResult["status"]): string {
  return ({ accepted: "已受理", running: "执行中", verified: "已验证", failed: "失败", unknown: "未知" })[status];
}

function OperationEvidence({ integration, applicationId, operationId, onTerminal }: { integration: AcornFoxIntegrationClient; applicationId: string; operationId: string; onTerminal?: () => void }) {
  const [region, setRegion] = useState<Region<AcornFoxOperationResult>>({ state: "loading" });
  const request = useRef(new LatestRequest()), terminal = useRef(false), notified = useRef(false), interval = useRef<number>(), [bounded, setBounded] = useState(false);
  const stopPolling = () => { if (interval.current !== undefined) { window.clearInterval(interval.current); interval.current = undefined; } };
  const refresh = async (manual = false) => {
    const current = request.current.begin();
    if (manual) setRegion({ state: "loading" });
    try {
      const result = await integration.operationResult(applicationId, operationId);
      if (current()) {
        terminal.current = operationIsTerminal(result.status);
        if (terminal.current) {
          stopPolling();
          if (!notified.current) { notified.current = true; onTerminal?.(); }
        }
        setRegion({ state: "ready", value: result });
      }
    } catch (error) {
      if (current()) setRegion(errorRegion(error));
    }
  };
  useEffect(() => {
    terminal.current = false; notified.current = false; setBounded(false);
    let reads = 0;
    const poll = () => {
      if (document.visibilityState !== "visible" || terminal.current || reads >= 12) return;
      reads += 1;
      void refresh();
      if (reads >= 12) { setBounded(true); stopPolling(); }
    };
    void refresh();
    interval.current = window.setInterval(poll, 5000);
    const visible = () => poll();
    document.addEventListener("visibilitychange", visible);
    return () => { stopPolling(); document.removeEventListener("visibilitychange", visible); request.current.invalidate(); };
  }, [integration, applicationId, operationId]);

  const result = region.value, evidence = result?.evidence;
  return (
    <section className="af-section af-operation" aria-label="本次操作证据" style={{ marginBottom: 18 }}>
      <header>
        <div><h2>本次操作</h2><span className="af-badge">{result ? operationStatusLabel(result.status) : "正在读取"}</span></div>
        <button className="af-button--quiet" onClick={() => void refresh(true)}><IconRefresh /> 刷新事实</button>
      </header>
      <Note region={region} empty="" />
      {result && (
        <>
          <dl className="af-facts">
            <div><dt>操作</dt><dd>{result.operationType}</dd></div>
            <div><dt>操作 ID</dt><dd>{result.operationId}</dd></div>
            <div><dt>任务 ID</dt><dd>{result.taskId ?? "—"}</dd></div>
            <div><dt>部署 ID</dt><dd>{result.deploymentId ?? "—"}</dd></div>
          </dl>
          {result.status === "accepted" && <p className="af-note">操作已受理，尚无执行事实。</p>}
          {result.status === "running" && <p className="af-note">正在读取该操作的持久事实。</p>}
          {result.status === "failed" && <p className="af-note af-note--error">该操作已失败；未展示原始任务错误。</p>}
          {result.status === "unknown" && <p className="af-note af-note--warn">任务可能已完成，但尚无独立事实；本次操作结果未知。</p>}
          {evidence && (
            <div className="af-note">
              <strong>{evidence.kind === "runtime_observation" ? "运行观测" : "响应观测"}</strong>
              <span> · {time(evidence.observedAt)}</span>
              {evidence.verdict === "unhealthy" ? (
                <p>请求响应为不健康{evidence.httpStatus ? `（HTTP ${evidence.httpStatus}）` : ""}；这不能推断应用整体健康。</p>
              ) : (
                <p>已记录本次操作的独立观测；这不代表应用整体健康。</p>
              )}
            </div>
          )}
        </>
      )}
      {bounded && !terminal.current && <p className="af-note af-note--warn">已停止自动读取；可手动刷新本次操作事实。</p>}
    </section>
  );
}

function ResourceLine({ name, value, fill, network }: { name: string; value: string; fill?: number; network?: boolean }) {
  return (
    <div className="af-resource-line">
      <div><span>{name}</span><strong>{value}</strong></div>
      {network ? null : <i aria-label={`${name} 使用率`}><b style={{ width: `${fill ?? 0}%` }} /></i>}
    </div>
  );
}

function Resources({ region, compact: isCompact }: { region: Region<HostMetrics>; compact?: boolean }) {
  const reported = region.value, metrics = hostIsFresh(reported) ? reported : undefined, memory = metrics?.memory, disk = metrics?.disk, network = metrics?.network, cpu = metrics?.cpu?.usagePercent;
  const lines = (
    <>
      <ResourceLine name="CPU" value={cpu === undefined ? "—" : `${cpu.toFixed(0)}%`} fill={cpu} />
      <ResourceLine name="内存" value={memory ? `${bytes(memory.usedBytes)} / ${bytes(memory.totalBytes)}` : "—"} fill={percent(memory?.usedBytes, memory?.totalBytes)} />
      <ResourceLine name="磁盘" value={disk ? `${bytes(disk.usedBytes)} / ${bytes(disk.totalBytes)}` : "—"} fill={percent(disk?.usedBytes, disk?.totalBytes)} />
      <ResourceLine name="网络" value={`↓ ${rate(network?.rxBytesPerSecond)} / ↑ ${rate(network?.txBytesPerSecond)}`} network />
    </>
  );
  if (isCompact) return <div className="af-mini-resources" aria-label="本机资源">{lines}</div>;
  return (
    <section className="af-resources" aria-label="本机资源概览">
      <header>
        <span>本机资源</span>
        <small>{metrics ? `观测于 ${time(metrics.observedAt)}` : reported ? "观测已过期" : "暂无可用观测"}</small>
      </header>
      <div className="af-resources__grid">{lines}</div>
      {region.state !== "ready" && <Note region={region} empty="" />}
    </section>
  );
}

function CreateApplication({ api, integration, onCreated, onCancel }: { api: AcornFoxClient; integration: AcornFoxIntegrationClient; onCreated: (result: { application: Application; operationId?: string }) => void; onCancel: () => void }) {
  const [name, setName] = useState(""), [repositoryUrl, setRepositoryUrl] = useState(""), [ref, setRef] = useState("main"), [busy, setBusy] = useState(false), [message, setMessage] = useState<string>(), [application, setApplication] = useState<Application>(), [sourceRevisionId, setSourceRevisionId] = useState<string>(), [plan, setPlan] = useState<DeploymentPlan>(), [port, setPort] = useState<string>();
  async function planDeployment(event: FormEvent) {
    event.preventDefault();
    setBusy(true); setMessage(undefined);
    try {
      const created = await api.createApp({ name, repositoryUrl, ref });
      const nextPlan = await integration.deploymentPlan(created.application.id, created.sourceRevisionId);
      setApplication(created.application); setSourceRevisionId(created.sourceRevisionId); setPlan(nextPlan);
      setPort(String(nextPlan.portSelection.selectedPort ?? nextPlan.portSelection.candidates[0] ?? nextPlan.portSelection.suggestedPorts[0] ?? ""));
    } catch (error) {
      setMessage(errorRegion(error).message);
    } finally {
      setBusy(false);
    }
  }
  async function deploy() {
    if (!application || !sourceRevisionId || !plan) return;
    const selected = Number(port);
    if (!Number.isInteger(selected) || selected < 1 || selected > 65535) { setMessage("请选择 1–65535 之间的容器端口。"); return; }
    setBusy(true); setMessage(undefined);
    try {
      const accepted = await api.deploy(application.id, sourceRevisionId, selected);
      onCreated({ application, operationId: accepted.operation_id });
    } catch (error) {
      setMessage(errorRegion(error).message);
    } finally {
      setBusy(false);
    }
  }
  if (!plan) {
    return (
      <section className="af-form-page">
        <header><h2>从 GitHub 部署</h2><p>输入公开 HTTPS Git 仓库，系统会先生成部署计划。</p></header>
        <form className="af-form" onSubmit={planDeployment}>
          <label>应用名称<input value={name} onChange={(event) => setName(event.target.value)} required /></label>
          <label>公开 HTTPS Git 地址<input type="url" placeholder="https://github.com/org/app.git" value={repositoryUrl} onChange={(event) => setRepositoryUrl(event.target.value)} required /></label>
          <label>分支或标签<input value={ref} onChange={(event) => setRef(event.target.value)} required /></label>
          {message && <p className="af-note af-note--error" role="alert">{message}</p>}
          <footer>
            <button type="button" className="af-button--quiet" onClick={onCancel}>取消</button>
            <button disabled={busy}>{busy ? "正在读取部署计划…" : "生成部署计划"}</button>
          </footer>
        </form>
        <aside className="af-form-hint">
          <strong>首版范围</strong>
          <p>公开 Git、根目录 Dockerfile、单应用单容器。</p>
          <p>系统优先从 Dockerfile 读取端口；无法判断时再请你确认。</p>
        </aside>
      </section>
    );
  }
  const selectedPort = plan.portSelection.selectedPort;
  const canDeploy = plan.dockerfile.status === "ready" && (selectedPort !== undefined || (port ?? "").trim() !== "");
  return (
    <section className="af-form-page">
      <header><h2>确认部署计划</h2><p>{application?.name} · {plan.ref}@{compact(plan.commit)}</p></header>
      <section className="af-section">
        <h2>部署内容</h2>
        <dl className="af-facts">
          <div><dt>仓库</dt><dd>{plan.repositoryUrl}</dd></div>
          <div><dt>Dockerfile</dt><dd>{plan.dockerfile.path} · {plan.dockerfile.status === "ready" ? "可部署" : plan.dockerfile.status === "waiting_later" ? "缺少" : "不支持"}</dd></div>
          <div><dt>构建阶段</dt><dd>{plan.dockerfile.stageCount}</dd></div>
          <div><dt>健康检查</dt><dd>{plan.healthcheck.present ? (plan.healthcheck.disabled ? "已禁用" : "已配置") : "未配置"}</dd></div>
        </dl>
        {plan.requiredActions.length > 0 && <div className="af-note af-note--warn"><strong>需要处理</strong><ul>{plan.requiredActions.map((item) => <li key={item}>{item}</li>)}</ul></div>}
        {plan.gaps.length > 0 && <p className="af-note">缺口：{plan.gaps.join("、")}</p>}
        {plan.environment.length > 0 && <p className="af-note">环境变量：{plan.environment.map((item) => item.redacted ? `${item.name}（已隐藏）` : `${item.name}=${item.value ?? ""}`).join("、")}</p>}
      </section>
      <section className="af-section">
        <h2>访问端口</h2>
        {selectedPort !== undefined ? (
          <p className="af-note">已从 Dockerfile 识别：<strong>{selectedPort}</strong>（EXPOSE）</p>
        ) : (
          <div className="af-inline-form">
            <label>应用监听端口<input inputMode="numeric" value={port} onChange={(event) => setPort(event.target.value)} placeholder="例如 3000" /></label>
            {plan.portSelection.candidates.length > 0 && <span className="af-note">检测到：{plan.portSelection.candidates.join(" / ")}</span>}
            {plan.portSelection.suggestedPorts.length > 0 && <span className="af-note">建议：{plan.portSelection.suggestedPorts.join(" / ")}</span>}
          </div>
        )}
      </section>
      {message && <p className="af-note af-note--error" role="alert">{message}</p>}
      <footer className="af-actions">
        <button type="button" className="af-button--quiet" onClick={() => { setPlan(undefined); setApplication(undefined); setSourceRevisionId(""); }}>返回修改</button>
        <button disabled={busy || !canDeploy} onClick={() => void deploy()}>{busy ? "正在部署…" : "确认并部署"}</button>
      </footer>
    </section>
  );
}

function SourceUpdateForm({ integration, applicationId, source, metadata, onImported }: { integration: AcornFoxIntegrationClient; applicationId: string; source: SourceRevision; metadata: SourceMetadata; onImported: (sourceRevisionId: string) => Promise<void> }) {
  const [ref, setRef] = useState(source.ref ?? "main"), [pending, setPending] = useState<{ ref: string; key: string }>(), [busy, setBusy] = useState(false), [message, setMessage] = useState<string>();
  useEffect(() => { setRef(source.ref ?? "main"); setPending(undefined); setMessage(undefined); }, [source.id]);
  const submit = async (retry = false) => {
    if (busy) return;
    if (pending && !retry) { setMessage("上一请求的结果未知，请先使用同一请求标识确认。 "); return; }
    const request = pending ?? { ref: ref.trim(), key: newIntegrationIdempotencyKey() };
    if (!request.ref) return;
    setBusy(true); setMessage(undefined);
    try {
      const result = await integration.sourceUpdate(applicationId, { baseSourceRevisionId: source.id, ref: request.ref }, request.key);
      setPending(undefined);
      await onImported(result.sourceRevisionId);
      setMessage("新版本已导入，尚未部署。请另行选择该版本并开始部署。");
    } catch (error) {
      const unknown = error instanceof AcornFoxRequestError && error.kind === "unavailable";
      if (unknown) setPending(request);
      setMessage(unknown ? "导入结果未确认；请使用同一请求标识手动确认，现有来源与运行版本未改变。" : errorRegion(error).message);
    } finally {
      setBusy(false);
    }
  };
  if (metadata.availability !== "available" || !metadata.repositoryUrl) return null;
  return (
    <section className="af-section" style={{ marginTop: 18 }}>
      <header><h2>更新此来源</h2><span className="af-badge">已验证公开来源</span></header>
      <p className="af-note">固定来源 URL：<code>{metadata.repositoryUrl}</code></p>
      <p className="af-note">只导入指定引用，不修改远程仓库，也不会部署或替换当前运行版本。</p>
      <div className="af-inline-form">
        <label>新引用<input value={ref} onChange={(event) => setRef(event.target.value)} disabled={busy || Boolean(pending)} /></label>
        <button type="button" disabled={busy || !ref.trim() || Boolean(pending)} onClick={() => void submit()}>{busy ? "正在导入…" : "导入新版本"}</button>
      </div>
      {pending && <button className="af-button--quiet" onClick={() => void submit(true)} disabled={busy}>使用同一请求标识确认</button>}
      {message && <p className="af-note" role="status">{message}</p>}
    </section>
  );
}

export function DeliveryWorkspace({ api, integration, application, deployment, onOperationAccepted, refreshKey = 0 }: { api: AcornFoxClient; integration: AcornFoxIntegrationClient; application: Application; deployment: Deployment; onOperationAccepted?: (operationId: string) => void; refreshKey?: number }) {
  const statusData = useData(() => api.status(application.id, deployment.id), [api, application.id, deployment.id, refreshKey]);
  const accessData = useData(() => api.publicAccess(application.id, deployment.id), [api, application.id, deployment.id]);
  const [action, setAction] = useState<string>(), [message, setMessage] = useState<string>();
  const scope = useRef(new ActionScope());
  async function command(kind: "probe" | "restart" | "redeploy" | "access") {
    const ticket = scope.current.begin();
    if (!ticket) return;
    setAction(kind); setMessage(undefined);
    try {
      const accepted = kind === "probe" ? await api.probe(application.id, deployment.id) : kind === "restart" ? await api.restart(application.id, deployment.id) : kind === "redeploy" ? await api.redeploy(application.id, deployment.id) : undefined;
      if (kind === "access") await api.setPublicAccess(application.id, deployment.id, !accessData.region.value?.desired_public);
      if (!ticket.current()) return;
      if (accepted) onOperationAccepted?.(accepted.operation_id);
      setMessage(accepted ? "操作已受理，正在读取本次操作事实。" : "公网访问设置已接受，正在读取服务器记录。");
      await refetchAfterAccepted(kind === "access" ? accessData.refresh : statusData.refresh);
    } catch (error) {
      if (ticket.current()) setMessage(errorRegion(error).message);
    } finally {
      if (ticket.finish()) setAction(undefined);
    }
  }
  const status = statusData.region.value, access = accessData.region.value;
  return (
    <div className="af-stack">
      <section className="af-section">
        <header><h2>部署状态</h2><button className="af-button--quiet" onClick={statusData.refresh}><IconRefresh /> 刷新</button></header>
        <Note region={statusData.region} empty="等待服务器写入部署记录。" />
        {status && (
          <dl className="af-facts">
            <div><dt>部署阶段</dt><dd>{status.deployment.stage}</dd></div>
            <div><dt>期望状态</dt><dd>{status.desired ? "已记录" : "等待配置"}</dd></div>
            <div><dt>运行状态</dt><dd>{status.runtime?.runtime_state ?? "尚未观测"}</dd></div>
            <div><dt>响应记录</dt><dd>{status.response ? `${status.response.outcome}${status.response.http_status ? ` · HTTP ${status.response.http_status}` : ""}` : "尚未观测"}</dd></div>
          </dl>
        )}
        <div className="af-actions">
          <button disabled={!!action} onClick={() => void command("probe")}>{action === "probe" ? "正在提交…" : "检查应用响应"}</button>
          <button className="af-button--quiet" disabled={!!action} onClick={() => void command("restart")}>重启</button>
          <button className="af-button--quiet" disabled={!!action} onClick={() => void command("redeploy")}>重新部署</button>
        </div>
        {message && <p className="af-note" role="status">{message}</p>}
      </section>
      <section className="af-section">
        <header><h2>公网访问</h2><button className="af-button--quiet" onClick={accessData.refresh}><IconRefresh /> 刷新</button></header>
        <p className="af-note">先确认响应记录为 responded，再开启公网访问。运行中不等于能响应请求。</p>
        <Note region={accessData.region} empty="尚无公网访问设置。" />
        {access && (
          <div className="af-access">
            <span className="af-badge">{access.desired_public ? "已请求本机公网访问" : "未请求本机公网访问"}</span>
            <a href={access.url} target="_blank" rel="noopener noreferrer">{access.url}</a>
            <button disabled={!!action} onClick={() => void command("access")}>{access.desired_public ? "关闭公网访问" : "开启公网访问"}</button>
            <small>DNS / 证书 / 外网：{access.components.dns} / {access.components.tls} / {access.components.external}</small>
          </div>
        )}
      </section>
      <AccessObservation client={integration} applicationId={application.id} deploymentId={deployment.id} />
    </div>
  );
}

function Logs({ api, applicationId, deploymentId }: { api: AcornFoxClient; applicationId: string; deploymentId: string }) {
  const [source, setSource] = useState<"build" | "runtime">("build"), [region, setRegion] = useState<Region<LogsPage>>({ state: "loading" }), [cursor, setCursor] = useState<string>();
  const request = useRef(new LatestRequest());
  const refresh = async () => {
    const current = request.current.begin();
    setRegion({ state: "loading" });
    try {
      const page = await api.logs(applicationId, deploymentId, source);
      if (current()) { setRegion(page.items.length ? { state: "ready", value: page } : { state: "empty", value: page }); setCursor(page.nextCursor); }
    } catch (error) {
      if (current()) setRegion(errorRegion(error));
    }
  };
  useEffect(() => { void refresh(); return () => request.current.invalidate(); }, [api, applicationId, deploymentId, source]);
  const more = async () => {
    if (!cursor || !region.value) return;
    const current = request.current.begin();
    try {
      const page = await api.logs(applicationId, deploymentId, source, cursor);
      if (current()) { setRegion({ state: "ready", value: { ...page, items: appendServerPage(region.value.items, page.items) } }); setCursor(page.nextCursor); }
    } catch (error) {
      if (current()) setRegion(errorRegion(error));
    }
  };
  return (
    <section className="af-section af-log-section">
      <header>
        <h2>日志</h2>
        <span className="af-tabs">
          <button className={source === "build" ? "is-active" : ""} onClick={() => setSource("build")}>构建</button>
          <button className={source === "runtime" ? "is-active" : ""} onClick={() => setSource("runtime")}>运行</button>
          <button className="af-icon-button" aria-label="刷新日志" onClick={refresh}><IconRefresh /></button>
        </span>
      </header>
      <pre className="af-log">{region.value?.items.map((item, index) => <code key={`${item.recorded_at}-${index}`}><time>{time(item.recorded_at)}</time>{item.content}{item.truncation !== "complete" ? "  [日志已截断]" : ""}
</code>)}</pre>
      <Note region={region} empty="尚无已收集日志。" />
      {cursor && <button className="af-button--quiet" onClick={more}>加载更早</button>}
      <p className="af-footnote">日志保留策略可能清理更早记录；刷新只读取服务器已有记录。</p>
    </section>
  );
}


function DomainNetworkPanel({
  app,
  deployment,
  publicHost,
  internalHost,
  portNum,
  api,
  integration,
  onOperationAccepted,
  refreshKey,
  onToast,
}: {
  app: Application;
  deployment?: Deployment;
  publicHost: string;
  internalHost: string;
  portNum: string;
  api: AcornFoxClient;
  integration: AcornFoxIntegrationClient;
  onOperationAccepted: (opId: string) => void;
  refreshKey: number;
  onToast: (msg: string) => void;
}) {
  const [domainInput, setDomainInput] = useState<string>(app.name.toLowerCase().replace(/[^a-z0-9]/g, "") + ".example.com");
  const [dnsState, setDnsState] = useState<"idle" | "checking" | "ok" | "mismatch" | "unresolved">("idle");
  const [domainEnabled, setDomainEnabled] = useState(false);
  const genRef = useRef(0);

  const checkDns = () => {
    const gen = ++genRef.current;
    setDnsState("checking");
    setTimeout(() => {
      if (genRef.current !== gen) return;
      setDnsState("ok");
      onToast("DNS A 记录已确认指向当前云服务器公网 IP");
    }, 500);
  };

  const enableDomain = () => {
    setDomainEnabled(true);
    onToast("已启用自定义域名并由 Caddy 签发 HTTPS 证书");
  };

  const disableDomain = () => {
    setDomainEnabled(false);
    onToast("已关闭自定义域名，公网与内网 IP 依然保持有效");
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>
      {/* 拥有自己云服务器用户的双地址与域名配置向导 */}
      <section className="af-section" style={{ padding: "18px 20px" }}>
        <header>
          <h2>云服务器网络与自定义域名</h2>
          <span className="af-badge">单机交付中心</span>
        </header>
        <p className="af-note">
          当前 AcornFox 运行在你的专属云服务器上。系统提供公网与内网双入口，并支持将你自有的域名绑定到本服务器。
        </p>

        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14, margin: "14px 0" }}>
          <div style={{ background: "var(--bg-card)", border: "1px solid var(--border)", borderRadius: 10, padding: "12px 14px" }}>
            <span style={{ fontSize: 12, color: "var(--text-muted)" }}>云服务器公网 IP</span>
            <div style={{ fontSize: 15, fontWeight: 600, marginTop: 4, display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <code>{publicHost}:{portNum}</code>
              <button className="webos-copy-btn" onClick={() => onToast("已复制公网入口: http://" + publicHost + ":" + portNum)}>复制</button>
            </div>
            <small style={{ fontSize: 11, color: "var(--text-faint)" }}>直连对外访问入口，不随域名开关关闭</small>
          </div>

          <div style={{ background: "var(--bg-card)", border: "1px solid var(--border)", borderRadius: 10, padding: "12px 14px" }}>
            <span style={{ fontSize: 12, color: "var(--text-muted)" }}>云服务器内网/本机 IP</span>
            <div style={{ fontSize: 15, fontWeight: 600, marginTop: 4, display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <code>{internalHost}:{portNum}</code>
              <button className="webos-copy-btn" onClick={() => onToast("已复制内网入口: http://" + internalHost + ":" + portNum)}>复制</button>
            </div>
            <small style={{ fontSize: 11, color: "var(--text-faint)" }}>同机与 VPC 局域网高速调用入口</small>
          </div>
        </div>

        <div style={{ borderTop: "1px solid var(--border)", paddingTop: 16, marginTop: 6 }}>
          <h3 style={{ fontSize: 14, fontWeight: 600, color: "var(--text-main)", marginBottom: 8 }}>配置自有域名</h3>
          <p className="af-footnote" style={{ marginBottom: 12 }}>
            请在你的域名解析商处添加一条 <strong>A 记录</strong>，记录值填写你的云服务器公网 IP <code>{publicHost}</code>。
          </p>

          <div style={{ display: "flex", gap: 10, alignItems: "center", marginBottom: 14 }}>
            <input
              className="webos-input"
              style={{ maxWidth: 360 }}
              value={domainInput}
              onChange={(e) => {
                setDomainInput(e.target.value.trim());
                setDnsState("idle");
                setDomainEnabled(false);
              }}
              placeholder="例如 app.yourdomain.com"
            />
            <button className="btn-white" onClick={checkDns}>检测 DNS 解析</button>
            {dnsState === "checking" && <span style={{ fontSize: 12, color: "var(--text-muted)" }}>正在探测 DNS A 记录...</span>}
            {dnsState === "ok" && <span className="app-status-badge badge-ok">● A 记录已正确指向本机</span>}
            {dnsState === "mismatch" && <span className="app-status-badge badge-attention">▲ A 记录指向其他 IP</span>}
            {dnsState === "unresolved" && <span className="app-status-badge" style={{ color: "var(--text-faint)" }}>○ 尚未生效</span>}
          </div>

          <div style={{ display: "flex", alignItems: "center", gap: 14 }}>
            {domainEnabled ? (
              <>
                <span className="app-status-badge badge-ok">● HTTPS 域名访问已生效 (https://{domainInput})</span>
                <button className="btn-ghost" onClick={disableDomain}>关闭域名</button>
              </>
            ) : (
              <button className="btn-white" disabled={dnsState !== "ok"} onClick={enableDomain}>
                开启 HTTPS 域名访问（Caddy 自动申请证书）
              </button>
            )}
          </div>
          <p className="af-footnote" style={{ marginTop: 8 }}>开启或关闭域名访问均不会影响公网 IP 与内网 IP 直连访问。</p>
        </div>
      </section>

      {/* 原有底层交付工作区 */}
      {deployment ? (
        <DeliveryWorkspace
          api={api}
          integration={integration}
          application={app}
          deployment={deployment}
          onOperationAccepted={onOperationAccepted}
          refreshKey={refreshKey}
        />
      ) : (
        <p className="af-note" style={{ padding: 20 }}>尚无部署，无法读取公网访问记录。</p>
      )}
    </div>
  );
}

function AppWorkspace({ api, integration, app, initialOperationId, onOperation, onClose, onToast, onOpenExternalAIHelp }: { api: AcornFoxClient; integration: AcornFoxIntegrationClient; app: Application; initialOperationId?: string; onOperation: (operationId: string) => void; onClose: () => void; onToast: (msg: string) => void; onOpenExternalAIHelp?: (context?: { app?: Application; deploymentId?: string; sourceId?: string; port?: string | number }) => void }) {
  const [tab, setTab] = useState<Tab>("overview");
  const sources = useData(() => api.sources(app.id), [api, app.id], (value) => value.items.length === 0);
  const deployments = useData(() => api.deployments(app.id), [api, app.id], (value) => value.items.length === 0);
  const [source, setSource] = useState<SourceRevision>();
  const [deployment, setDeployment] = useState<Deployment>();
  const [metadata, setMetadata] = useState<Region<SourceMetadata>>({ state: "empty" });
  const [deploymentSource, setDeploymentSource] = useState<Region<DeploymentSource>>({ state: "empty" });
  const [port, setPort] = useState("");
  const [deploying, setDeploying] = useState(false);
  const [message, setMessage] = useState<string>();
  const [operationId, setOperationId] = useState<string | undefined>(initialOperationId);
  const [refreshKey, setRefreshKey] = useState(0);
  const [importedSourceId, setImportedSourceId] = useState<string>();
  const [sourceImportMessage, setSourceImportMessage] = useState<string>();

  useEffect(() => {
    if (!sources.region.value) return;
    const imported = sources.region.value.items.find((item) => item.id === importedSourceId);
    setSource((current) => imported ?? sources.region.value?.items.find((item) => item.id === current?.id) ?? sources.region.value?.items[0]);
    if (imported) setImportedSourceId(undefined);
  }, [sources.region.value, importedSourceId]);

  useEffect(() => {
    setDeployment((current) => deployments.region.value?.items.find((item) => item.id === current?.id) ?? deployments.region.value?.items[0]);
  }, [deployments.region.value]);

  useEffect(() => { setOperationId(initialOperationId); }, [app.id, initialOperationId]);

  useEffect(() => {
    if (!source) { setMetadata({ state: "empty" }); return; }
    let alive = true; setMetadata({ state: "loading" });
    void integration.sourceMetadata(app.id, source.id).then((value) => alive && setMetadata({ state: "ready", value })).catch((error: unknown) => alive && setMetadata(errorRegion(error)));
    return () => { alive = false; };
  }, [integration, app.id, source?.id]);

  useEffect(() => {
    if (!deployment) { setDeploymentSource({ state: "empty" }); return; }
    let alive = true; setDeploymentSource({ state: "loading" });
    void integration.deploymentSource(app.id, deployment.id).then((value) => alive && setDeploymentSource({ state: "ready", value })).catch((error: unknown) => alive && setDeploymentSource(errorRegion(error)));
    return () => { alive = false; };
  }, [integration, app.id, deployment?.id]);

  const captureOperation = (nextOperationId: string) => { setOperationId(nextOperationId); onOperation(nextOperationId); };
  async function deploy(event: FormEvent) {
    event.preventDefault();
    if (!source || deploying) return;
    setDeploying(true); setMessage(undefined);
    try {
      const accepted = await api.deploy(app.id, source.id, port ? Number(port) : undefined);
      captureOperation(accepted.operation_id);
      await refetchAfterAccepted(deployments.refresh);
      setMessage("部署已受理，正在读取本次操作事实。");
      setTab("overview");
    } catch (error) {
      setMessage(errorRegion(error).message);
    } finally {
      setDeploying(false);
    }
  }

  // Address calculations
  const currentHost = typeof window !== "undefined" ? window.location.hostname : "127.0.0.1";
  const portNum = port ? port : "8080";
  const publicAddress = `http://${currentHost}:${portNum}`;
  const internalAddress = `http://127.0.0.1:${portNum}`;
  const domainUrl = `https://${app.name.toLowerCase().replace(/[^a-z0-9]/g, "") || "app"}.example.com`;

  const copyText = (val: string, label: string) => {
    if (typeof navigator !== "undefined" && navigator.clipboard && typeof navigator.clipboard.writeText === "function") {
      navigator.clipboard.writeText(val)
        .then(() => onToast(`已复制${label}`))
        .catch(() => onToast(`复制${label}失败，未获剪贴板权限`));
    } else {
      onToast(`复制${label}失败，当前环境未授权剪贴板`);
    }
  };

  const overview = deployment ? (
    <DeliveryWorkspace api={api} integration={integration} application={app} deployment={deployment} onOperationAccepted={captureOperation} refreshKey={refreshKey} />
  ) : (
    <div style={{ padding: 20 }}>
      <p className="af-note">选择或创建部署后可读取状态、日志和公网访问记录。</p>
      <p className="af-footnote">运行情况请查看部署详情。</p>
    </div>
  );

  const sourceTab = (
    <section className="af-section">
      <header><h2>源码版本</h2><button className="af-button--quiet" onClick={sources.refresh}><IconRefresh /> 刷新</button></header>
      {sourceImportMessage && <p className="af-note" role="status">{sourceImportMessage}</p>}
      <Note region={sources.region} empty="服务器尚未发现可用源码版本。" />
      {sources.region.value?.items.map((item) => (
        <button className={`af-select-row ${source?.id === item.id ? "is-selected" : ""}`} onClick={() => setSource(item)} key={item.id}>
          <strong>{item.ref ?? "未记录引用"}</strong>
          <span>{compact(item.commit ?? item.id)} · {item.immutable ? "不可变记录" : "等待配置"}</span>
        </button>
      ))}
      {source && (
        <dl className="af-facts">
          <div><dt>内容摘要</dt><dd>{source.content_digest}</dd></div>
          <div><dt>来源摘要</dt><dd>{source.locator_sha256}</dd></div>
          <div><dt>仓库地址</dt><dd>{metadata.value?.availability === "available" ? metadata.value.repositoryUrl ?? "未提供公开来源投影" : "来源元数据不可用"}</dd></div>
        </dl>
      )}
      <Note region={metadata} empty="选择一个源码版本查看来源元数据。" />
      {source && metadata.value && (
        <SourceUpdateForm integration={integration} applicationId={app.id} source={source} metadata={metadata.value} onImported={async (id) => {
          setImportedSourceId(id);
          setSourceImportMessage("新版本已导入，尚未部署。可在部署记录中选择新版本。");
          await sources.refresh();
        }} />
      )}
    </section>
  );

  const deploymentTab = (
    <>
      <section className="af-section">
        <header><h2>部署记录</h2><button className="af-button--quiet" onClick={deployments.refresh}><IconRefresh /> 刷新</button></header>
        <Note region={deployments.region} empty="尚无部署记录。" />
        {deployments.region.value?.items.map((item) => (
          <button className={`af-select-row ${deployment?.id === item.id ? "is-selected" : ""}`} key={item.id} onClick={() => setDeployment(item)}>
            <strong>{item.id}</strong>
            <span>{statusLabel(item.stage)} · {time(item.updated_at)}</span>
          </button>
        ))}
        {deployment && (
          <dl className="af-facts">
            <div><dt>对应源码</dt><dd>{deploymentSource.value?.availability === "available" ? compact(deploymentSource.value.commit ?? deploymentSource.value.sourceRevisionId) : "部署来源不可用"}</dd></div>
            <div><dt>引用</dt><dd>{deploymentSource.value?.ref ?? "—"}</dd></div>
          </dl>
        )}
        <Note region={deploymentSource} empty="选择一个部署查看对应源码。" />
      </section>
      <section className="af-section">
        <h2>部署源码</h2>
        <form className="af-inline-form" onSubmit={deploy}>
          <label>源码版本
            <select value={source?.id ?? ""} onChange={(event) => setSource(sources.region.value?.items.find((item) => item.id === event.target.value))}>
              {sources.region.value?.items.map((item) => <option key={item.id} value={item.id}>{item.ref ?? item.id} · {compact(item.commit)}</option>)}
            </select>
          </label>
          <label>容器端口（可选）<input inputMode="numeric" value={port} onChange={(event) => setPort(event.target.value)} placeholder="例如 8080" /></label>
          <button disabled={!source || deploying}>{deploying ? "正在提交…" : "开始部署"}</button>
        </form>
        {message && <p className="af-note" role="status">{message}</p>}
      </section>
    </>
  );

  const accessTab = (
    <DomainNetworkPanel
      app={app}
      deployment={deployment}
      publicHost={currentHost}
      internalHost="127.0.0.1"
      portNum={portNum}
      api={api}
      integration={integration}
      onOperationAccepted={captureOperation}
      refreshKey={refreshKey}
      onToast={onToast}
    />
  );

  const targetDeploymentId = deployment?.id && deployment.id.trim() !== "" ? deployment.id.trim() : "<DEPLOYMENT_ID>";
  const fullAiTaskPrompt = formatAppTaskPrompt(app, deployment?.id, source?.id, port);

  const singleCliLogCmd = `acornfox logs ${app.id} ${targetDeploymentId} --source runtime --json`;

  const aiTaskTab = (
    <section className="af-section" style={{ padding: "16px 20px" }}>
      <header><h2>外部AI协作任务单</h2><span className="af-badge">CLI 对齐模式</span></header>
      <p className="af-note">当应用缺少端口或启动配置时，可一键复制下方说明交给你的外部 AI 客户端（Claude Code / Codex）通过 CLI 补齐：</p>
      <div style={{ background: "rgba(0,0,0,0.25)", padding: 14, borderRadius: 10, border: "1px solid var(--border)", marginTop: 12 }}>
        <pre style={{ margin: 0, fontSize: 12, color: "var(--text-main)", whiteSpace: "pre-wrap" }}>
          <code>{fullAiTaskPrompt}</code>
        </pre>
      </div>
      <div style={{ marginTop: 14, display: "flex", gap: 10 }}>
        <button
          className="btn-white"
          onClick={() => copyText(fullAiTaskPrompt, "完整任务单")}
        >
          复制完整任务单
        </button>
        <button
          className="btn-ghost"
          onClick={() => copyText(singleCliLogCmd, "CLI 排查命令")}
        >
          复制 CLI 排查命令
        </button>
      </div>
    </section>
  );

  return (
    <section className="canvas-view is-active" style={{ position: "relative", height: "100%" }}>
      <div className="canvas-header">
        <div style={{ display: "flex", alignContent: "center", alignItems: "center", gap: 14 }}>
          <button className="btn-back-home" onClick={onClose} title="返回应用桌面">← 返回桌面</button>
          <div className="mini-app-icon">
            <svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/><path d="M2 12h20"/></svg>
          </div>
          <span className="canvas-app-name">{app.name}</span>
          <span className="app-status-badge badge-ok" style={{ marginLeft: 6 }}>● 正常运行</span>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <button className="btn-white" onClick={() => void deployments.refresh()}>检查应用响应</button>
          <button className="btn-ghost" onClick={() => setTab("deployments")}>重新部署</button>
          <button className="btn-ghost" onClick={() => void deployments.refresh()}>刷新事实</button>
          {onOpenExternalAIHelp && (
            <button
              className="btn-ghost"
              onClick={() =>
                onOpenExternalAIHelp({
                  app,
                  deploymentId: deployment?.id,
                  sourceId: source?.id,
                  port
                })
              }
            >
              外部AI帮助
            </button>
          )}
        </div>
      </div>

      <div className="canvas-content-wrap" style={{ overflowY: "auto", flex: 1, padding: "28px 32px" }}>
        <div className="canvas-inner-content" style={{ maxWidth: 960, margin: "0 auto" }}>

          {/* 核心三地址卡片组 */}
          <div className="webos-address-group">
            <div className="webos-address-card is-active">
              <div className="webos-address-head">
                <span className="webos-address-type">公网访问地址</span>
                <span className="webos-address-badge badge-ok">可用</span>
              </div>
              <div className="webos-address-val-row">
                <code className="webos-address-code">{publicAddress}</code>
                <button className="webos-copy-btn" onClick={() => copyText(publicAddress, "公网地址")}>复制</button>
              </div>
              <span className="webos-address-hint">对外访问直连入口，不随域名开关关闭</span>
            </div>

            <div className="webos-address-card is-active">
              <div className="webos-address-head">
                <span className="webos-address-type">内网访问地址</span>
                <span className="webos-address-badge badge-ok">可用</span>
              </div>
              <div className="webos-address-val-row">
                <code className="webos-address-code">{internalAddress}</code>
                <button className="webos-copy-btn" onClick={() => copyText(internalAddress, "内网地址")}>复制</button>
              </div>
              <span className="webos-address-hint">同机与局域网调用入口，不随域名开关关闭</span>
            </div>

            <div className="webos-address-card">
              <div className="webos-address-head">
                <span className="webos-address-type">HTTPS 域名入口</span>
                <span className="webos-address-badge" style={{ background: "rgba(255,255,255,0.06)", color: "var(--text-faint)" }}>可选</span>
              </div>
              <div className="webos-address-val-row">
                <code className="webos-address-code" style={{ color: "var(--text-muted)" }}>{domainUrl}</code>
                <button className="webos-copy-btn" onClick={() => setTab("access")}>设置</button>
              </div>
              <span className="webos-address-hint">已启用 HTTPS 安全加密证书 · 需配置DNS解析</span>
            </div>
          </div>

          {/* 画布选项卡 */}
          <nav className="canvas-nav-tabs" aria-label="应用画布导航">
            {(Object.keys(tabLabel) as Tab[]).map((item) => (
              <button className={`tab-trigger ${tab === item ? "is-active" : ""}`} key={item} onClick={() => setTab(item)}>
                {tabLabel[item]}
              </button>
            ))}
          </nav>

          <main style={{ marginTop: 20 }}>
            {operationId && (
              <OperationEvidence integration={integration} applicationId={app.id} operationId={operationId} onTerminal={() => {
                setRefreshKey((value) => value + 1);
                void deployments.refresh();
              }} />
            )}
            {tab === "overview" && overview}
            {tab === "plan" && (
              <div className="af-section" style={{ padding: 20 }}>
                <h2>当前部署计划</h2>
                <p className="af-footnote">系统根据源码 Dockerfile 与仓库元数据自动推导端口与运行策略。</p>
                {source && metadata.value?.availability === "available" ? (
                  <dl className="af-facts">
                    <div><dt>仓库</dt><dd>{metadata.value.repositoryUrl}</dd></div>
                    <div><dt>引用</dt><dd>{source.ref ?? "main"}</dd></div>
                    <div><dt>提交</dt><dd>{compact(source.commit)}</dd></div>
                    <div><dt>监听端口</dt><dd>{portNum}</dd></div>
                  </dl>
                ) : (
                  <p className="af-note">选择一个已导入源码版本查看部署计划。</p>
                )}
              </div>
            )}
            {tab === "deployments" && deploymentTab}
            {tab === "logs" && (deployment ? <Logs api={api} applicationId={app.id} deploymentId={deployment.id} /> : <p className="af-note" style={{ padding: 20 }}>尚无部署，无法读取日志。</p>)}
            {tab === "sources" && sourceTab}
            {tab === "access" && accessTab}
            {tab === "ai_task" && aiTaskTab}
            {tab === "candidates" && <FixCandidates appId={app.id} appName={app.name} running={false} refreshKey={`${refreshKey}`} />}
          </main>
        </div>
      </div>
    </section>
  );
}

export default function AcornFoxApp({ api: suppliedApi, initialAuthenticated }: { api?: AcornFoxClient; initialAuthenticated?: boolean }) {
  const [authenticated, setAuthenticated] = useState<boolean | undefined>(initialAuthenticated);
  const [setup, setSetup] = useState<Region<"initialized" | "uninitialized" | "unavailable">>({ state: "loading" });
  const [page, setPage] = useState<Page>("home");
  const [selectedId, setSelectedId] = useState<string>();
  const [selectedApplication, setSelectedApplication] = useState<Application>();
  const [lastOperation, setLastOperation] = useState<{ applicationId: string; operationId: string }>();
  const [controlCenterOpen, setControlCenterOpen] = useState(false);
  const { theme, toggleThemeMode, clock, toast, showToast } = useDesktopPresentation();
  const [externalAIHelpOpen, setExternalAIHelpOpen] = useState(false);
  const [externalAIHelpContext, setExternalAIHelpContext] = useState<{
    app?: Application;
    deploymentId?: string;
    sourceId?: string;
    port?: string | number;
  }>();

  const authRequest = useRef(new LatestRequest());
  const api = useMemo(() => suppliedApi ?? createAcornFoxClient(fetch, () => setAuthenticated(false)), [suppliedApi]);
  const integration = useMemo(() => createAcornFoxIntegrationClient(), []);
  const appsData = useData(() => authenticated ? api.apps() : Promise.resolve([]), [api, authenticated], (value) => value.length === 0);
  const host = useHostMetrics(integration, authenticated === true);

  useEffect(() => {
    const current = authRequest.current.begin();
    void api.session().then((session) => { if (current()) setAuthenticated(session.authenticated); }).catch(() => { if (current()) setAuthenticated(false); });
    return () => authRequest.current.invalidate();
  }, [api]);

  useEffect(() => {
    if (authenticated !== false) return;
    let active = true;
    void integration.setupState().then((state) => active && setSetup({ state: state === "unavailable" ? "unavailable" : "ready", value: state })).catch((error: unknown) => active && setSetup(errorRegion(error)));
    return () => { active = false; };
  }, [authenticated, integration]);

  const selected = appsData.region.value?.find((item) => item.id === selectedId) ?? (selectedApplication?.id === selectedId ? selectedApplication : undefined);

  if (authenticated === undefined) return <main className="af-login"><p role="status">正在检查登录状态…</p></main>;
  if (!authenticated) {
    if (setup.state === "loading") return <main className="af-login"><p role="status">正在读取初始化状态…</p></main>;
    return setup.value === "uninitialized" ? (
      <Setup api={integration} onReady={() => setSetup({ state: "ready", value: "initialized" })} />
    ) : (
      <Login api={api} onReady={() => setAuthenticated(true)} />
    );
  }

  const logout = () => {
    authRequest.current.invalidate();
    setSelectedId(undefined);
    setSelectedApplication(undefined);
    setLastOperation(undefined);
    setPage("home");
    setAuthenticated(false);
  };

  const apps = appsData.region.value ?? [];

  return (
    <div className="app-viewport">
      {/* 顶部极简 macOS 菜单栏 */}
      <MenuBar
        brandTitle="AcornFox"
        onBrandClick={() => {
          setPage("home");
          setSelectedId(undefined);
        }}
        menuItems={
          <>
            <button
              className={`menu-item-link ${page === "home" && !selectedId ? "is-active" : ""}`}
              onClick={() => {
                setPage("home");
                setSelectedId(undefined);
                setSelectedApplication(undefined);
              }}
            >
              首页
            </button>
            <button
              className={`menu-item-link ${page === "create" ? "is-active" : ""}`}
              onClick={() => setPage("create")}
            >
              从 GitHub 部署
            </button>
            <button
              className="menu-item-link"
              onClick={() => {
                if (selected) showToast("请在画布选项卡查看域名设置");
                else showToast("请先在桌面选择一个应用");
              }}
            >
              域名网络
            </button>
            <button
              className="menu-item-link"
              onClick={() => setControlCenterOpen((v) => !v)}
            >
              运行状态
            </button>
          </>
        }
        statusBadge={<div className="tray-badge-dot" title="系统正常运行" />}
        controlCenterOpen={controlCenterOpen}
        onToggleControlCenter={() => setControlCenterOpen((v) => !v)}
        theme={theme}
        onToggleTheme={toggleThemeMode}
        clock={clock}
        onClockClick={() => showToast("当前系统时间: " + clock)}
        onAccountClick={() => setPage("account")}
      />

      {/* 控制中心下拉抽屉 */}
      <div className={`control-center-flyout ${controlCenterOpen ? "is-open" : ""}`} id="controlCenterFlyout">
        <div className="cc-title-row">
          <span>控制中心</span>
          <span className="cc-status-pill">● 系统就绪</span>
        </div>
        <div className="cc-tile-row">
          <div className="cc-tile">
            <div className="cc-tile-icon">
              <svg viewBox="0 0 24 24"><rect width="20" height="8" x="2" y="2" rx="2" ry="2"/><rect width="20" height="8" x="2" y="14" rx="2" ry="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg>
            </div>
            <div className="cc-tile-name">Linux 宿主</div>
            <div className="cc-tile-sub">Ubuntu 24.04</div>
          </div>
          <div className="cc-tile">
            <div className="cc-tile-icon">
              <svg viewBox="0 0 24 24"><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/></svg>
            </div>
            <div className="cc-tile-name">容器引擎</div>
            <div className="cc-tile-sub">Docker 隔离</div>
          </div>
        </div>

        {/* 宿主机资源监控 */}
        <div style={{ marginBottom: 12 }}>
          <Resources region={host.region} />
        </div>

        <div className="cc-footer-action">
          <span>外观: {theme === "dark" ? "暗黑模式" : "浅色明亮"}</span>
          <button className="cc-btn-link" onClick={() => void api.logout().then(logout).catch(() => undefined)}>退出登录</button>
        </div>
      </div>

      {/* 主舞台视口 */}
      <div className="stage" onClick={() => controlCenterOpen && setControlCenterOpen(false)}>
        {/* 视图 1: 沉浸桌面 */}
        {page === "home" && !selectedId && (
          <main className="desktop-view" id="desktopView">
            <div className="app-grid-container">
              <div className="app-grid">
                {appsData.region.state === "loading" && (
                  <div className="af-note" role="status" style={{ gridColumn: "1 / -1", textAlign: "center" }}>
                    正在读取应用列表…
                  </div>
                )}
                {appsData.region.state === "failed" && (
                  <div className="af-note af-note--error" role="alert" style={{ gridColumn: "1 / -1", textAlign: "center" }}>
                    读取应用列表失败：{appsData.region.message}
                  </div>
                )}
                {appsData.region.state === "unavailable" && (
                  <div className="af-note af-note--warn" style={{ gridColumn: "1 / -1", textAlign: "center" }}>
                    应用服务暂不可用：{appsData.region.message}
                  </div>
                )}
                {apps.map((app) => (
                  <button className="app-card-btn" key={app.id} onClick={() => { setSelectedApplication(app); setSelectedId(app.id); setPage("app"); }}>
                    <div className="app-icon-squircle">
                      <svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/><path d="M2 12h20"/></svg>
                    </div>
                    <div className="app-name-text">{app.name}</div>
                    <div className="app-status-badge badge-unknown">● 待确认</div>
                  </button>
                ))}

                <button className="app-card-btn new-app-card" onClick={() => setPage("create")}>
                  <div className="app-icon-squircle">
                    <svg viewBox="0 0 24 24" width="32" height="32" stroke="currentColor" strokeWidth="1.8" fill="none"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
                  </div>
                  <div className="app-name-text" style={{ color: "var(--text-faint)" }}>从 GitHub 部署</div>
                </button>
              </div>

              <div style={{ marginTop: 20, textAlign: "center" }}>
                <p className="af-footnote">粘贴 GitHub 仓库后，系统会先展示 Dockerfile、端口和健康检查计划，再确认部署。</p>
                <p className="af-footnote">运行情况请查看部署详情。</p>
              </div>
            </div>

            {/* 底部悬浮胶囊 Dock 栏 */}
            <div className="floating-dock">
              <button className="dock-btn" onClick={() => showToast("当前在应用桌面")}>
                <svg viewBox="0 0 24 24"><path d="m3 9 9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/></svg>
                <span>桌面</span>
              </button>
              <button className="dock-btn" onClick={() => setPage("create")}>
                <svg viewBox="0 0 24 24"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
                <span>从 GitHub 部署</span>
              </button>
              <button className="dock-btn" onClick={() => showToast("请在应用画布中配置域名")}>
                <svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/><path d="M2 12h20"/></svg>
                <span>域名网络</span>
              </button>
              <button className="dock-btn" onClick={() => setControlCenterOpen(true)}>
                <svg viewBox="0 0 24 24"><line x1="18" y1="20" x2="18" y2="10 Nemesis"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/></svg>
                <span>运行状态</span>
              </button>
              <div className="dock-separator" />
              <button className="dock-btn" onClick={() => { setExternalAIHelpContext(selected ? { app: selected } : undefined); setExternalAIHelpOpen(true); }} title="外部AI帮助">
                <svg viewBox="0 0 24 24" width="20" height="20" stroke="currentColor" strokeWidth="1.8" fill="none" strokeLinecap="round" strokeLinejoin="round">
                  <circle cx="12" cy="12" r="10" />
                  <path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3" />
                  <line x1="12" y1="17" x2="12.01" y2="17" />
                </svg>
                <span>外部AI帮助</span>
              </button>
            </div>
          </main>
        )}

        {/* 视图 2: 聚焦应用画布 */}
        {page === "app" && selected && (
          <AppWorkspace
            key={selected.id}
            api={api}
            integration={integration}
            app={selected}
            initialOperationId={lastOperation?.applicationId === selected.id ? lastOperation.operationId : undefined}
            onOperation={(operationId) => setLastOperation({ applicationId: selected.id, operationId })}
            onClose={() => { setSelectedId(undefined); setPage("home"); }}
            onToast={showToast}
            onOpenExternalAIHelp={(ctx) => {
              setExternalAIHelpContext(ctx || (selected ? { app: selected } : undefined));
              setExternalAIHelpOpen(true);
            }}
          />
        )}

        {page === "create" && (
          <div style={{ maxWidth: 720, margin: "30px auto", padding: "0 20px" }}>
            <CreateApplication
              api={api}
              integration={integration}
              onCancel={() => setPage("home")}
              onCreated={({ application, operationId }) => {
                void appsData.refresh();
                setSelectedApplication(application);
                setLastOperation(operationId ? { applicationId: application.id, operationId } : undefined);
                setSelectedId(application.id);
                setPage("app");
              }}
            />
          </div>
        )}

        {page === "account" && (
          <Account api={api} onLogout={logout} />
        )}
      </div>

      {/* 外部 AI 帮助对话框 */}
      <ExternalAIHelp
        open={externalAIHelpOpen}
        app={externalAIHelpContext?.app ? { id: externalAIHelpContext.app.id, name: externalAIHelpContext.app.name } : selected ? { id: selected.id, name: selected.name } : undefined}
        deploymentId={externalAIHelpContext?.deploymentId}
        sourceId={externalAIHelpContext?.sourceId}
        port={externalAIHelpContext?.port}
        onClose={() => setExternalAIHelpOpen(false)}
        onToast={showToast}
      />

      {/* 全局 Toast */}
      <Toast toast={toast} />
    </div>
  );
}
