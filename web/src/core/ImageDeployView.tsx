import { useEffect, useRef, useState, type FormEvent } from "react";
import { AcornFoxRequestError, imageDomainHostname, type CoreAuthClient, type ImagePlan, type ImageOperation, type ImageLifecycleAction, type ImageLifecycleOperation, type ManagedImageApplicationSummary, type ManagedImageObservation, type ManagedImageMetrics, type ManagedImageMetricsRecent, type ManagedImageMetricPoint, type ImageDomainAction, type ImageDomainCurrent, type ImageDomainOperation } from "../shared/auth-transport";
import "./image-deploy.css";

const states = { pending: "等待执行", running: "执行中", unknown: "结果未知，请继续核对已有操作", succeeded: "执行成功", failed: "执行失败", cancelled: "已取消" };
const terminal = (state: ImageOperation["state"]) => ["succeeded", "failed", "cancelled"].includes(state);
const errorText = (error: unknown) => error instanceof AcornFoxRequestError ? `${error.message}（${error.code}）` : error instanceof Error ? error.message : "请求未完成。";

export type ImageLifecycleAttempt = {
  key: string; action: ImageLifecycleAction; deploymentId: string; releaseId: string;
  deployOperationId: string; applicationId: string; environmentId: string; planId: string; planDigest: string; manifestDigest: string; containerId: string;
  imageId: string; hostPort: number; containerPort: number;
  operationId: string; operation: ImageLifecycleOperation | null;
};
export const lifecycleLocked = (attempt: ImageLifecycleAttempt | null) => Boolean(attempt && (!attempt.operation || !terminal(attempt.operation.state)));
export function savedImageSelectionLocked(confirmationAttempted: boolean, confirmKey: string, operation: ImageOperation | null, lifecycle: ImageLifecycleAttempt | null): boolean {
  return Boolean((confirmationAttempted && confirmKey && (!operation || !terminal(operation.state))) || (lifecycle?.key && lifecycleLocked(lifecycle)));
}
export function availableImageLifecycleActions(operation: ImageOperation | null): ImageLifecycleAction[] {
  const result = operation?.result;
  if (operation?.state !== "succeeded" || !result?.container_id || !result.image_id || !result.host_port || !result.container_port) return [];
  return result.status === "running" ? ["stop", "restart"] : result.status === "stopped" ? ["start"] : [];
}
export function prepareImageLifecycleAttempt(operation: ImageOperation, action: ImageLifecycleAction, key: string, previous: ImageLifecycleAttempt | null, manifestDigest: string): ImageLifecycleAttempt {
  if (lifecycleLocked(previous) || !availableImageLifecycleActions(operation).includes(action) || !key) throw new Error("请先核对当前部署状态，并等待已有操作收束。");
  const result = operation.result!;
  return { key, action, deploymentId: result.deployment_id, releaseId: result.release_id, deployOperationId: operation.operation_id,
    applicationId: operation.application_id, environmentId: operation.environment_id, planId: operation.plan_id, planDigest: operation.plan_digest, manifestDigest, containerId: result.container_id!, imageId: result.image_id!,
    hostPort: result.host_port!, containerPort: result.container_port!, operationId: "", operation: null };
}
export function bindImageLifecycleResponse(attempt: ImageLifecycleAttempt, value: ImageLifecycleOperation): ImageLifecycleAttempt {
  if ((attempt.operationId && value.operation_id !== attempt.operationId) || value.operation_id === attempt.deployOperationId || value.deploy_operation_id !== attempt.deployOperationId || value.deployment_id !== attempt.deploymentId || value.release_id !== attempt.releaseId || value.action !== attempt.action || value.plan_id !== attempt.planId || value.plan_digest !== attempt.planDigest || value.manifest_digest !== attempt.manifestDigest || value.application_id !== attempt.applicationId || value.environment_id !== attempt.environmentId || value.container_id !== attempt.containerId || value.image_id !== attempt.imageId || value.host_port !== attempt.hostPort || value.container_port !== attempt.containerPort) throw new Error("生命周期响应与当前受管部署不一致；请保留同一操作键核对。");
  return { ...attempt, operationId: value.operation_id, operation: value };
}
export function validateImageDeploymentReadback(value: ImageOperation, attempt: ImageLifecycleAttempt | null): ImageOperation {
  if (attempt) {
    const result = value.result;
    if (value.operation_id !== attempt.deployOperationId || value.application_id !== attempt.applicationId || value.environment_id !== attempt.environmentId || value.plan_id !== attempt.planId || value.plan_digest !== attempt.planDigest || !result || result.deployment_id !== attempt.deploymentId || result.release_id !== attempt.releaseId || result.container_id !== attempt.containerId || result.image_id !== attempt.imageId || result.host_port !== attempt.hostPort || result.container_port !== attempt.containerPort) throw new Error("部署查询响应与已有受管身份不一致，已暂停查询。");
  }
  return value;
}
export function visibleImageEndpoint(operation: ImageOperation | null, attempt: ImageLifecycleAttempt | null, fresh = true): string {
  if (!fresh || lifecycleLocked(attempt) || operation?.state !== "succeeded" || operation.result?.status !== "running" || (attempt?.operation?.state === "succeeded" && !attempt.operation.result?.running)) return "";
  return operation.result.endpoint ?? "";
}

export type ManagedImageObservationTarget = { deploymentId: string; containerId: string; imageId: string; manifestDigest: string; hostPort: number; containerPort: number };
export function managedImageObservationTarget(operation: ImageOperation | null, plan: ImagePlan | null): ManagedImageObservationTarget | null {
  const result = operation?.result;
  if (operation?.state !== "succeeded" || !plan || plan.id !== operation.plan_id || plan.plan_digest !== operation.plan_digest || !result?.container_id || !result.image_id || !result.host_port || !result.container_port || !["running", "stopped"].includes(result.status)) return null;
  return { deploymentId: result.deployment_id, containerId: result.container_id, imageId: result.image_id, manifestDigest: plan.resolved_image.digest, hostPort: result.host_port, containerPort: result.container_port };
}
export function bindManagedImageObservation(value: ManagedImageObservation, target: ManagedImageObservationTarget): ManagedImageObservation {
  const state = value.state;
  if (!state.verified_identity || state.endpoint_ready || state.container_id !== target.containerId || state.image_id !== target.imageId || state.manifest_digest !== target.manifestDigest || state.host_port !== target.hostPort || state.container_port !== target.containerPort) throw new Error("容器观测响应与当前受管应用不一致，未显示数据。");
  return value;
}
export const currentManagedImageObservation = (requestScope: string, currentScope: string, requestEpoch: number, currentEpoch: number, signal: AbortSignal) => !signal.aborted && requestScope === currentScope && requestEpoch === currentEpoch;

export type ImageDomainAttempt = { key: string; deploymentId: string; hostname: string; action: ImageDomainAction; operationId: string; operation: ImageDomainOperation | null };
export const imageDomainLocked = (attempt: ImageDomainAttempt | null) => Boolean(attempt && (!attempt.operation || !terminal(attempt.operation.state)));
export const imageDomainSelectionLocked = (attempt: ImageDomainAttempt | null, current: ImageDomainCurrent | null) => imageDomainLocked(attempt) || Boolean(current && !terminal(current.operation.state));
export function bindImageDomainOperation(value: ImageDomainOperation, deploymentId: string, expected?: ImageDomainOperation | ImageDomainAttempt): ImageDomainOperation {
  const expectedID = expected && ("operation_id" in expected ? expected.operation_id : expected.operationId);
  if (value.deployment_id !== deploymentId || (expected && ((expectedID && value.operation_id !== expectedID) || value.hostname !== expected.hostname || value.action !== expected.action))) throw new Error("域名操作与当前受管部署不一致，已暂停控制。");
  if (expected && "approval_id" in expected && (value.approval_id !== expected.approval_id || value.task_id !== expected.task_id || value.created_at !== expected.created_at)) throw new Error("域名操作身份发生变化，已暂停控制。");
  return value;
}
export function bindImageDomainCurrent(value: ImageDomainCurrent, deploymentId: string, deploymentStatus: string): ImageDomainCurrent {
  bindImageDomainOperation(value.operation, deploymentId);
  if (value.deployment_status !== deploymentStatus) throw new Error("域名状态与最新部署状态不一致，请重新读取。暂不允许新操作。");
  return value;
}
export async function readCurrentImageDomain(api: CoreAuthClient, deploymentId: string, deploymentStatus: string, signal: AbortSignal): Promise<ImageDomainCurrent | null> {
  const current = await api.imageDomainCurrent(deploymentId, signal);
  if (!current) return null;
  bindImageDomainCurrent(current, deploymentId, deploymentStatus);
  const operation = bindImageDomainOperation(await api.imageDomainOperation(current.operation.operation_id, signal), deploymentId, current.operation);
  if (operation.state !== current.operation.state || JSON.stringify(operation.result) !== JSON.stringify(current.operation.result)) throw new Error("域名操作在读取期间变化，请重新查询当前状态。");
  return current;
}

export function createManagedImageReadQueue() {
  let tail: Promise<void> = Promise.resolve();
  return async <T,>(signal: AbortSignal, read: () => Promise<T>): Promise<T> => {
    const previous = tail;
    let release!: () => void;
    tail = new Promise<void>((resolve) => { release = resolve; });
    try {
      await previous;
      if (signal.aborted) { const error = new Error("The operation was aborted"); error.name = "AbortError"; throw error; }
      return await read();
    } finally { release(); }
  };
}

export function bindManagedImageMetrics(value: ManagedImageMetrics, recent: ManagedImageMetricsRecent, target: ManagedImageObservationTarget) {
  bindManagedImageObservation({ state: value.state, source_limited: false }, target);
  if (recent.deployment_id !== target.deploymentId || recent.container_id !== target.containerId) throw new Error("指标历史与当前受管容器不一致，未显示数据。");
  return { current: value, recent };
}

// Preserve actual timestamps and separate process generations. Missing or
// unavailable readings break a line; they never become a zero reading.
export function imageMemorySegments(recent: ManagedImageMetricsRecent): ManagedImageMetricPoint[][] {
  const segments: ManagedImageMetricPoint[][] = []; let current: ManagedImageMetricPoint[] = [];
  for (const point of recent.samples) {
    const previous = current[current.length - 1];
    const gap = previous ? Date.parse(point.observed_at) - Date.parse(previous.observed_at) : 0;
    if (!point.available || point.memory_usage_bytes === undefined || (previous && (point.segment_id !== previous.segment_id || point.container_id !== previous.container_id || gap > recent.stale_after_seconds * 1000 || gap <= 0))) {
      if (current.length) segments.push(current);
      current = [];
    }
    if (point.available && point.memory_usage_bytes !== undefined) current.push(point);
  }
  if (current.length) segments.push(current);
  return segments;
}

function memoryBytes(value: number | undefined): string {
  if (value === undefined) return "不可用";
  if (value < 1024) return `${value} B`;
  const units = ["KiB", "MiB", "GiB", "TiB"];
  let size = value / 1024, index = 0;
  while (size >= 1024 && index < units.length - 1) { size /= 1024; index++; }
  return `${size.toFixed(size >= 100 ? 0 : 1)} ${units[index]}`;
}
function metricValue(value: number | undefined, suffix = ""): string { return value === undefined ? "不可用" : `${value}${suffix}`; }
function metricTime(value: string | undefined): string { return value ? new Date(value).toLocaleString("zh-CN", { hour12: false }) : "暂无"; }

function ImageMemoryTrend({ recent }: { recent: ManagedImageMetricsRecent }) {
  const segments = imageMemorySegments(recent);
  const points = segments.flat();
  if (!points.length) return <p>近期没有可绘制的内存采样；未观测到的值不会画成零。</p>;
  const width = 320, height = 76, pad = 6;
  const times = recent.samples.map((point) => Date.parse(point.observed_at));
  const first = Math.min(...times), last = Math.max(...times);
  const peak = Math.max(0, ...points.map((point) => point.memory_usage_bytes ?? 0));
  const scalePeak = Math.max(1, peak);
  const x = (point: ManagedImageMetricPoint) => pad + (last === first ? (width - 2 * pad) / 2 : (Date.parse(point.observed_at) - first) / (last - first) * (width - 2 * pad));
  const y = (point: ManagedImageMetricPoint) => height - pad - (point.memory_usage_bytes ?? 0) / scalePeak * (height - 2 * pad);
  return <div className="image-metrics-trend">
    <svg viewBox={`0 0 ${width} ${height}`} preserveAspectRatio="none" role="img" aria-label={`内存近期趋势，${points.length} 个真实采样，按进程段与缺口断线`}>
      <line x1={pad} x2={width - pad} y1={height - pad} y2={height - pad} className="image-metrics-grid" />
      {segments.map((segment, index) => segment.length === 1 ? <circle key={index} cx={x(segment[0])} cy={y(segment[0])} r="2.5" className="image-metrics-dot" /> :
        <polyline key={index} points={segment.map((point) => `${x(point)},${y(point)}`).join(" ")} className="image-metrics-line" />)}
    </svg>
    <div className="image-metrics-axis"><span>{metricTime(recent.samples[0]?.observed_at)}</span><span>最高 {memoryBytes(peak)}</span><span>{metricTime(recent.samples[recent.samples.length - 1]?.observed_at)}</span></div>
  </div>;
}
function recentMetricsStatus(recent: ManagedImageMetricsRecent): string {
  if (recent.recording_status === "not_selected") return recent.selection_limited ? "当前采样容量已满，此应用未入选近期记录。" : "此应用当前未入选近期记录。";
  if (recent.reason === "not_running") return "容器当前未运行；近期记录中的历史值不代表当前用量。";
  if (recent.reason === "read_unavailable" || recent.reason === "runtime_changed" || recent.reason === "read_failed") return "本次指标读取不可用，近期记录可能有缺口。";
  if (recent.recording_status === "warming_up") return "近期记录正在预热，尚无保留的采样。";
  if (recent.stale || recent.recording_status === "stale") return "近期记录已过期；请刷新后核对。";
  return "近期记录中；仅展示实际取得的采样。";
}

// Selection restores durable identities through normal GETs. It never restores
// or invents an idempotency key, and does not create a deployment.
export async function readSavedImageApplication(api: CoreAuthClient, selected: ManagedImageApplicationSummary, signal: AbortSignal) {
  const currentList = await api.imageApps(100, signal);
  const item = currentList.items.find((value) => value.application_id === selected.application_id);
  if (!item) throw new Error(currentList.truncated ? "当前受限列表未包含此应用；已停止恢复，请重新选择，不创建替代应用。" : "当前账户未查到此应用，已停止恢复。");
  const [plan, initialOperation] = await Promise.all([api.imagePlan(item.plan_id, signal), api.imageOperation(item.deploy_operation_id, signal)]);
  let operation = initialOperation;
  if (plan.id !== item.plan_id || plan.plan_digest !== item.plan_digest || operation.operation_id !== item.deploy_operation_id || operation.plan_id !== item.plan_id || operation.plan_digest !== item.plan_digest || operation.application_id !== item.application_id || operation.environment_id !== item.environment_id || (item.deployment_id && operation.result?.deployment_id !== item.deployment_id)) throw new Error("已保存应用的计划或操作身份不一致，未恢复控制。");
  const summary = item.active_command ?? item.last_command;
  let lifecycle: ImageLifecycleAttempt | null = null;
  let history: ImageLifecycleOperation | null = null;
  if (summary) {
    const value = await api.imageLifecycleOperation(summary.operation_id, signal);
    const result = operation.result;
    if (!result || value.operation_id !== summary.operation_id || value.action !== summary.action || value.deploy_operation_id !== operation.operation_id || value.application_id !== item.application_id || value.environment_id !== item.environment_id || value.plan_id !== plan.id || value.plan_digest !== plan.plan_digest || value.manifest_digest !== plan.resolved_image.digest || value.deployment_id !== result.deployment_id || value.release_id !== result.release_id || value.container_id !== result.container_id || value.image_id !== result.image_id || value.host_port !== result.host_port || value.container_port !== result.container_port) throw new Error("已有生命周期操作不属于当前受管应用，未恢复控制。");
    if (item.active_command && terminal(value.state)) {
      const refreshed = await api.imageOperation(item.deploy_operation_id, signal);
      if (refreshed.operation_id !== operation.operation_id || refreshed.application_id !== operation.application_id || refreshed.environment_id !== operation.environment_id || refreshed.plan_id !== plan.id || refreshed.plan_digest !== plan.plan_digest || !refreshed.result || refreshed.result.deployment_id !== value.deployment_id || refreshed.result.release_id !== value.release_id || refreshed.result.container_id !== value.container_id || refreshed.result.image_id !== value.image_id || refreshed.result.host_port !== value.host_port || refreshed.result.container_port !== value.container_port) throw new Error("操作收束后的部署身份未核对，未恢复控制。");
      operation = refreshed;
    }
    if (!item.active_command || terminal(value.state)) history = value;
    else lifecycle = { key: "", action: value.action, operationId: value.operation_id, operation: value, deploymentId: value.deployment_id, releaseId: value.release_id, deployOperationId: value.deploy_operation_id, applicationId: value.application_id, environmentId: value.environment_id, planId: value.plan_id, planDigest: value.plan_digest, manifestDigest: value.manifest_digest, containerId: value.container_id, imageId: value.image_id, hostPort: value.host_port, containerPort: value.container_port };
  }
  return { plan, operation, lifecycle, history };
}

export function ImageDeployView({ api, active, onBack, onAuthenticationFailure }: {
  api: CoreAuthClient; active: boolean; onBack: () => void; onAuthenticationFailure: () => void;
}) {
  const [savedApps, setSavedApps] = useState<ManagedImageApplicationSummary[]>([]);
  const [listError, setListError] = useState("");
  const [listTruncated, setListTruncated] = useState(false);
  const [listRefresh, setListRefresh] = useState(0);
  const [selectedApp, setSelectedApp] = useState("");
  const [savedCommandHistory, setSavedCommandHistory] = useState<ImageLifecycleOperation | null>(null);
  const [appName, setAppName] = useState("");
  const [image, setImage] = useState("");
  const [port, setPort] = useState("");
  const [environment, setEnvironment] = useState("");
  const [plan, setPlan] = useState<ImagePlan | null>(null);
  const [operationId, setOperationId] = useState("");
  const [operation, setOperation] = useState<ImageOperation | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [pollError, setPollError] = useState("");
  const [refresh, setRefresh] = useState(0);
  const [confirmationAttempted, setConfirmationAttempted] = useState(false);
  const [lifecycleAttempt, setLifecycleAttempt] = useState<ImageLifecycleAttempt | null>(null);
  const lifecycleRef = useRef<ImageLifecycleAttempt | null>(null);
  const [lifecyclePollError, setLifecyclePollError] = useState("");
  const [lifecycleRefresh, setLifecycleRefresh] = useState(0);
  const [domainCurrent, setDomainCurrent] = useState<ImageDomainCurrent | null>(null);
  const [domainLoaded, setDomainLoaded] = useState(false);
  const [domainHostname, setDomainHostname] = useState("");
  const [domainAttempt, setDomainAttempt] = useState<ImageDomainAttempt | null>(null);
  const domainAttemptRef = useRef<ImageDomainAttempt | null>(null);
  const [domainBusy, setDomainBusy] = useState(false);
  const [domainError, setDomainError] = useState("");
  const [domainPollError, setDomainPollError] = useState("");
  const [domainRefresh, setDomainRefresh] = useState(0);
  const [domainPollRefresh, setDomainPollRefresh] = useState(0);
  const domainEpoch = useRef(0);
  const domainController = useRef<AbortController | null>(null);
  const domainScope = useRef("");
  const saveDomainAttempt = (value: ImageDomainAttempt | null) => { domainAttemptRef.current = value; setDomainAttempt(value); };
  const cancelDomainRead = () => {
    domainEpoch.current += 1; domainController.current?.abort(); domainController.current = null;
    setDomainBusy(false); setDomainCurrent(null); setDomainLoaded(false); setDomainError(""); setDomainPollError("");
  };
  const [deploymentFresh, setDeploymentFresh] = useState(true);
  const deploymentFreshRef = useRef(true);
  const markDeploymentFresh = (value: boolean) => { deploymentFreshRef.current = value; setDeploymentFresh(value); };
  const [containerSample, setContainerSample] = useState<{ value: ManagedImageObservation["state"]; receivedAt: number } | null>(null);
  const [logSample, setLogSample] = useState<{ records: NonNullable<ManagedImageObservation["records"]>; limited: boolean; observedAt: string } | null>(null);
  const [observationBusy, setObservationBusy] = useState(false);
  const [observationError, setObservationError] = useState("");
  const [observationCancelled, setObservationCancelled] = useState(false);
  const [sampleClock, setSampleClock] = useState(performance.now());
  const [metricsSample, setMetricsSample] = useState<{ scope: string; current: ManagedImageMetrics; recent: ManagedImageMetricsRecent; receivedAt: number } | null>(null);
  const [metricsBusy, setMetricsBusy] = useState(false);
  const [metricsError, setMetricsError] = useState("");
  const [metricsClock, setMetricsClock] = useState(performance.now());
  const metricsEpoch = useRef(0);
  const metricsController = useRef<AbortController | null>(null);
  const metricsScope = useRef("");
  const cancelMetrics = () => {
    metricsEpoch.current += 1; metricsController.current?.abort(); metricsController.current = null;
    setMetricsBusy(false); setMetricsSample(null); setMetricsError("");
  };
  const observationEpoch = useRef(0);
  const observationController = useRef<AbortController | null>(null);
  const observationScope = useRef("");
  const readQueue = useRef(createManagedImageReadQueue());
  const cancelObservation = (cancelled = false) => {
    observationEpoch.current += 1; observationController.current?.abort(); observationController.current = null;
    setObservationBusy(false); setContainerSample(null); setLogSample(null); setObservationError(""); setObservationCancelled(cancelled);
  };
  const saveLifecycle = (value: ImageLifecycleAttempt | null) => { lifecycleRef.current = value; setLifecycleAttempt(value); };
  const lifecyclePending = lifecycleLocked(lifecycleAttempt);
  const intentKey = useRef("");
  const selectionLocked = savedImageSelectionLocked(confirmationAttempted, intentKey.current, operation, lifecycleRef.current) || imageDomainSelectionLocked(domainAttempt, domainCurrent);

  const epoch = useRef(0);
  const controller = useRef<AbortController | null>(null);
  const inFlight = useRef(false);
  const authFailure = useRef(onAuthenticationFailure);
  authFailure.current = onAuthenticationFailure;

  useEffect(() => {
    return () => { epoch.current += 1; controller.current?.abort(); inFlight.current = false; };
  }, [active, api]);
  useEffect(() => { if (active) { setBusy(false); if (operationId) markDeploymentFresh(false); } }, [active, api]);

  const report = (err: unknown) => {
    if (err instanceof AcornFoxRequestError && err.kind === "authentication") {
      cancelObservation(); cancelMetrics(); cancelDomainRead(); saveDomainAttempt(null); epoch.current += 1; controller.current?.abort(); inFlight.current = false;
      setSavedApps([]); setSelectedApp(""); setSavedCommandHistory(null); setPlan(null); setOperationId(""); setOperation(null); saveLifecycle(null); markDeploymentFresh(false);
      authFailure.current();
    }
    return errorText(err);
  };
  const run = async (work: (signal: AbortSignal, current: () => boolean) => Promise<void>) => {
    if (!active || inFlight.current) return;
    inFlight.current = true; setBusy(true); setError("");
    const request = new AbortController(); controller.current = request;
    const generation = ++epoch.current;
    const current = () => generation === epoch.current && !request.signal.aborted;
    try { await work(request.signal, current); }
    catch (err) { if (current()) setError(report(err)); }
    finally { if (current()) { inFlight.current = false; setBusy(false); controller.current = null; } }
  };

  useEffect(() => {
    if (!active) return;
    const request = new AbortController(); let disposed = false;
    setListError("");
    void api.imageApps(50, request.signal).then((value) => {
      if (!disposed && !request.signal.aborted) { setSavedApps(value.items); setListTruncated(value.truncated); }
    }).catch((err) => { if (!disposed && !request.signal.aborted) { setSavedApps([]); setListError(report(err)); } });
    return () => { disposed = true; request.abort(); };
  }, [api, active, listRefresh]);

  const selectSaved = (id: string) => {
    if (savedImageSelectionLocked(confirmationAttempted, intentKey.current, operation, lifecycleRef.current) || imageDomainSelectionLocked(domainAttemptRef.current, domainCurrent) || (inFlight.current && intentKey.current && !operationId)) return;
    const item = savedApps.find((value) => value.application_id === id);
    if (!item) return;
    cancelObservation(); cancelMetrics(); cancelDomainRead(); saveDomainAttempt(null); epoch.current += 1; controller.current?.abort(); inFlight.current = false;
    setSelectedApp(id); setSavedCommandHistory(null); saveLifecycle(null); setOperation(null); setOperationId(""); setPlan(null);
    intentKey.current = ""; setConfirmationAttempted(true); markDeploymentFresh(false); setPollError(""); setLifecyclePollError("");
    void run(async (signal, current) => {
      const value = await readSavedImageApplication(api, item, signal);
      if (!current()) return;
      setPlan(value.plan); setOperationId(value.operation.operation_id); setOperation(value.operation); saveLifecycle(value.lifecycle); setSavedCommandHistory(value.history);
      markDeploymentFresh(!lifecycleLocked(value.lifecycle));
    });
  };

  const createPlan = (event: FormEvent) => {
    event.preventDefault();
    void run(async (signal, current) => {
      const env: Record<string, string> = Object.create(null) as Record<string, string>;
      for (const line of environment.split("\n").filter((v) => v.trim())) {
        const index = line.indexOf("=");
        const name = line.slice(0, index).trim();
        if (index < 1 || !/^[A-Za-z_][A-Za-z0-9_]*$/.test(name) || Object.hasOwn(env, name)) throw new Error("环境变量请逐行填写 NAME=value，名称不能重复。");
        env[name] = line.slice(index + 1);
      }
      const value = await api.createImagePlan({ app_name: appName.trim(), image: image.trim(), port: port ? Number(port) : undefined, environment: env }, signal);
      if (!current()) return;
      cancelObservation(); cancelMetrics(); cancelDomainRead(); saveDomainAttempt(null); setSelectedApp(""); setSavedCommandHistory(null); setListRefresh((v) => v + 1);
      intentKey.current = crypto.randomUUID();
      setPlan(value); setConfirmationAttempted(false); setOperationId(""); setOperation(null); setPollError(""); saveLifecycle(null); markDeploymentFresh(true); setLifecyclePollError("");
    });
  };
  const confirm = () => {
    if (!plan || plan.status !== "planned" || operationId || !intentKey.current || selectedApp) return;
    void run(async (signal, current) => {
      setConfirmationAttempted(true);
      const value = await api.confirmImagePlan({ plan_id: plan.id, plan_digest: plan.plan_digest, idempotency_key: intentKey.current }, signal);
      if (!current()) return;
      if (value.plan_id !== plan.id || value.plan_digest !== plan.plan_digest) throw new Error("确认响应与当前计划不一致，请核对服务状态；当前确认键已保留。");
      setOperationId(value.operation_id);
    });
  };

  useEffect(() => {
    if (!active || !operationId || !plan || lifecyclePending) return;
    const request = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    let disposed = false; const selectedEpoch = epoch.current;
    const poll = async () => {
      markDeploymentFresh(false);
      try {
        const value = await api.imageOperation(operationId, request.signal);
        if (disposed || request.signal.aborted || selectedEpoch !== epoch.current || lifecycleLocked(lifecycleRef.current)) return;
        if (value.operation_id !== operationId || value.plan_id !== plan.id || value.plan_digest !== plan.plan_digest) throw new Error("操作响应与已确认计划不一致，已停止自动查询。");
        validateImageDeploymentReadback(value, lifecycleRef.current);
        setOperation(value); setPollError(""); markDeploymentFresh(true);
        if (!terminal(value.state)) timer = setTimeout(() => void poll(), 3000);
      } catch (err) {
        if (!disposed && !request.signal.aborted && selectedEpoch === epoch.current) { markDeploymentFresh(false); setPollError(report(err)); }
      }
    };
    void poll();
    return () => { disposed = true; request.abort(); if (timer) clearTimeout(timer); };
  }, [api, active, operationId, plan, refresh, lifecyclePending]);

  const submitLifecycle = (attempt: ImageLifecycleAttempt) => {
    if (!attempt.key) return;
    void run(async (signal, current) => {
      const value = await api.createImageLifecycle(attempt.deploymentId, { action: attempt.action, idempotency_key: attempt.key }, signal);
      if (!current()) return;
      const latest = lifecycleRef.current;
      if (!latest || latest.key !== attempt.key) return;
      const accepted = bindImageLifecycleResponse(latest, value);
      // Same-key replay returns original pending acceptance; retain a newer
      // observation instead of replacing unknown/terminal state with pending.
      saveLifecycle({ ...accepted, operation: latest.operation ?? accepted.operation });
      setLifecyclePollError(""); setLifecycleRefresh((v) => v + 1);
    });
  };
  const beginLifecycle = (action: ImageLifecycleAction) => {
    if (!operation || !plan || busy || !deploymentFreshRef.current || pollError || lifecycleLocked(lifecycleRef.current) || imageDomainLocked(domainAttemptRef.current) || (domainCurrent && !terminal(domainCurrent.operation.state))) return;
    const attempt = prepareImageLifecycleAttempt(operation, action, crypto.randomUUID(), lifecycleRef.current, plan.resolved_image.digest);
    cancelObservation(); cancelMetrics(); saveLifecycle(attempt); markDeploymentFresh(false); setLifecyclePollError(""); submitLifecycle(attempt);
  };
  useEffect(() => {
    const attempt = lifecycleAttempt;
    if (!active || !attempt?.operationId) return;
    const request = new AbortController(); let disposed = false; const selectedEpoch = epoch.current;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const poll = async () => {
      try {
        const value = await api.imageLifecycleOperation(attempt.operationId, request.signal);
        const latest = lifecycleRef.current;
        if (disposed || request.signal.aborted || selectedEpoch !== epoch.current || !latest || latest.key !== attempt.key) return;
        saveLifecycle(bindImageLifecycleResponse(latest, value)); setLifecyclePollError("");
        if (terminal(value.state)) { markDeploymentFresh(false); setRefresh((v) => v + 1); }
        else timer = setTimeout(() => void poll(), 3000);
      } catch (err) {
        if (!disposed && !request.signal.aborted && selectedEpoch === epoch.current) setLifecyclePollError(report(err));
      }
    };
    void poll();
    return () => { disposed = true; request.abort(); if (timer) clearTimeout(timer); };
  }, [api, active, lifecycleAttempt?.operationId, lifecycleRefresh]);
  const effectiveFresh = deploymentFresh && !pollError;
  const endpoint = visibleImageEndpoint(operation, lifecycleAttempt, effectiveFresh);
  const refreshDeployment = () => { markDeploymentFresh(false); setRefresh((v) => v + 1); };
  const observationTarget = effectiveFresh && !lifecyclePending ? managedImageObservationTarget(operation, plan) : null;
  const observationKey = active && observationTarget ? JSON.stringify(observationTarget) : "";
  observationScope.current = observationKey;
  metricsScope.current = observationKey;
  const loadObservation = async (logs: boolean, target: ManagedImageObservationTarget) => {
    const scope = JSON.stringify(target);
    if (!active || !observationKey || observationScope.current !== scope) return;
    cancelObservation(); setObservationBusy(true);
    const request = new AbortController(); observationController.current = request;
    const generation = ++observationEpoch.current;
    const current = () => currentManagedImageObservation(scope, observationScope.current, generation, observationEpoch.current, request.signal);
    try {
      const value = await readQueue.current(request.signal, () => logs ? api.imageLogs(target.deploymentId, { tail: 64 }, request.signal) : api.imageObservation(target.deploymentId, request.signal));
      if (!current()) return;
      bindManagedImageObservation(value, target);
      const receivedAt = performance.now(); setSampleClock(receivedAt); setContainerSample({ value: value.state, receivedAt });
      if (logs) setLogSample({ records: value.records ?? [], limited: value.source_limited, observedAt: value.state.observed_at });
    } catch (err) {
      if (current()) { setContainerSample(null); setLogSample(null); setObservationError(report(err)); }
    } finally {
      if (current()) { setObservationBusy(false); observationController.current = null; }
    }
  };
  useEffect(() => {
    cancelObservation();
    if (observationKey && observationTarget) void loadObservation(false, observationTarget);
    return () => { observationEpoch.current += 1; observationController.current?.abort(); observationController.current = null; };
  }, [api, active, observationKey]);
  useEffect(() => {
    if (!active || !containerSample) return;
    const timer = setInterval(() => setSampleClock(performance.now()), 1000);
    return () => clearInterval(timer);
  }, [active, containerSample]);
  const observationStale = containerSample ? sampleClock - containerSample.receivedAt > 10000 : false;
  const loadMetrics = async (target: ManagedImageObservationTarget) => {
    const scope = JSON.stringify(target);
    if (!active || !observationKey || metricsScope.current !== scope) return;
    metricsEpoch.current += 1; metricsController.current?.abort(); metricsController.current = null;
    setMetricsBusy(true); setMetricsError("");
    const request = new AbortController(); metricsController.current = request;
    const generation = metricsEpoch.current;
    const current = () => currentManagedImageObservation(scope, metricsScope.current, generation, metricsEpoch.current, request.signal);
    try {
      const sample = await readQueue.current(request.signal, () => api.imageMetrics(target.deploymentId, request.signal));
      if (!current()) return;
      const recent = await readQueue.current(request.signal, () => api.imageMetricsRecent(target.deploymentId, 60, request.signal));
      if (!current()) return;
      bindManagedImageMetrics(sample, recent, target);
      const receivedAt = performance.now(); setMetricsClock(receivedAt); setMetricsSample({ scope, current: sample, recent, receivedAt }); setMetricsError("");
    } catch (err) {
      if (current()) {
        const message = report(err);
        if (current()) { setMetricsError(message); }
      }
    } finally {
      if (current()) { setMetricsBusy(false); metricsController.current = null; }
    }
  };
  useEffect(() => {
    cancelMetrics();
    if (observationKey && observationTarget) void loadMetrics(observationTarget);
    const timer = observationKey && observationTarget ? setInterval(() => void loadMetrics(observationTarget), 30000) : undefined;
    return () => { if (timer) clearInterval(timer); metricsEpoch.current += 1; metricsController.current?.abort(); metricsController.current = null; };
  }, [api, active, observationKey]);
  useEffect(() => {
    if (!active || !metricsSample) return;
    const timer = setInterval(() => setMetricsClock(performance.now()), 1000);
    return () => clearInterval(timer);
  }, [active, metricsSample]);
  const shownMetrics = metricsSample?.scope === observationKey ? metricsSample : null;
  const metricsAgeExpired = shownMetrics ? metricsClock - shownMetrics.receivedAt > shownMetrics.recent.stale_after_seconds * 1000 : false;
  const currentMetricsStale = shownMetrics ? Boolean(metricsError) || metricsClock - shownMetrics.receivedAt > 10000 : false;
  const domainTarget = selectedApp ? managedImageObservationTarget(operation, plan) : null;
  const domainKey = active && domainTarget ? JSON.stringify(domainTarget) : "";
  domainScope.current = domainKey;
  const loadDomain = async (target: ManagedImageObservationTarget, status: string) => {
    const scope = JSON.stringify(target);
    if (!active || !effectiveFresh || lifecyclePending || domainScope.current !== scope) return;
    cancelDomainRead(); setDomainBusy(true);
    const request = new AbortController(); domainController.current = request;
    const generation = ++domainEpoch.current;
    const current = () => currentManagedImageObservation(scope, domainScope.current, generation, domainEpoch.current, request.signal);
    try {
      const value = await readCurrentImageDomain(api, target.deploymentId, status, request.signal);
      if (!current()) return;
      if (!value && imageDomainLocked(domainAttemptRef.current)) throw new Error("已有域名操作尚未收束，当前状态未返回；请保留操作键核对。");
      setDomainCurrent(value); setDomainLoaded(true); setDomainError("");
      if (value && !terminal(value.operation.state) && !domainAttemptRef.current) saveDomainAttempt({ key: "", deploymentId: target.deploymentId, hostname: value.operation.hostname, action: value.operation.action, operationId: value.operation.operation_id, operation: value.operation });
    } catch (err) {
      if (current()) { const message = report(err); if (current()) setDomainError(message); }
    } finally {
      if (current()) { setDomainBusy(false); domainController.current = null; }
    }
  };
  useEffect(() => {
    cancelDomainRead();
    if (domainKey && domainTarget && effectiveFresh && !lifecyclePending && operation?.result) void loadDomain(domainTarget, operation.result.status);
    return () => { domainEpoch.current += 1; domainController.current?.abort(); domainController.current = null; };
  }, [api, active, domainKey, effectiveFresh, lifecyclePending, operation?.result?.status, domainRefresh]);
  const submitDomain = (attempt: ImageDomainAttempt) => {
    if (!attempt.key) return;
    void run(async (signal, current) => {
      const value = await api.createImageDomainCommand(attempt.deploymentId, { hostname: attempt.hostname, action: attempt.action, idempotency_key: attempt.key }, signal);
      if (!current()) return;
      const latest = domainAttemptRef.current;
      if (!latest || latest.key !== attempt.key || latest.deploymentId !== attempt.deploymentId) return;
      bindImageDomainOperation(value, attempt.deploymentId, latest.operation ?? latest);
      saveDomainAttempt({ ...latest, operationId: value.operation_id, operation: latest.operation ?? value });
      setDomainPollError(""); setDomainRefresh((v) => v + 1);
    });
  };
  const beginDomain = (action: ImageDomainAction) => {
    if (!domainTarget || !operation?.result || !effectiveFresh || lifecyclePending || busy || domainBusy || !domainLoaded || domainError || imageDomainLocked(domainAttemptRef.current) || (domainCurrent && !terminal(domainCurrent.operation.state))) return;
    if (action === "ensure" && operation.result.status !== "running") return;
    if (action === "remove" && (!domainCurrent || domainCurrent.local_route_state === "disabled")) return;
    try {
      const hostname = imageDomainHostname(action === "ensure" ? domainHostname : domainCurrent!.operation.hostname);
      if (action === "ensure" && domainCurrent && hostname !== domainCurrent.operation.hostname) throw new Error("已有受管域名只能使用原域名重新绑定。");
      const attempt: ImageDomainAttempt = { key: crypto.randomUUID(), deploymentId: domainTarget.deploymentId, hostname, action, operationId: "", operation: null };
      saveDomainAttempt(attempt); setDomainError(""); submitDomain(attempt);
    } catch (err) { setDomainError(err instanceof AcornFoxRequestError && err.code === "invalid_response" ? "请输入规范的小写公网域名。" : errorText(err)); }
  };
  useEffect(() => {
    const attempt = domainAttempt;
    if (!active || !domainKey || !attempt?.operationId || terminal(attempt.operation?.state ?? "pending")) return;
    const request = new AbortController(); let disposed = false; let timer: ReturnType<typeof setTimeout> | undefined;
    const scope = domainKey;
    const poll = async () => {
      try {
        const value = bindImageDomainOperation(await api.imageDomainOperation(attempt.operationId, request.signal), attempt.deploymentId, attempt.operation ?? attempt);
        const latest = domainAttemptRef.current;
        if (disposed || request.signal.aborted || domainScope.current !== scope || !latest || latest.operationId !== attempt.operationId) return;
        saveDomainAttempt({ ...latest, operation: value }); setDomainPollError("");
        if (terminal(value.state)) setDomainRefresh((v) => v + 1);
        else timer = setTimeout(() => void poll(), 3000);
      } catch (err) {
        if (!disposed && !request.signal.aborted && domainScope.current === scope) { const message = report(err); if (domainScope.current === scope) setDomainPollError(message); }
      }
    };
    void poll();
    return () => { disposed = true; request.abort(); if (timer) clearTimeout(timer); };
  }, [api, active, domainKey, domainAttempt?.operationId, domainAttempt?.operation?.state, domainPollRefresh]);
  const domainPending = imageDomainSelectionLocked(domainAttempt, domainCurrent);
  const actionNames: Record<ImageLifecycleAction, string> = { stop: "停止", start: "启动", restart: "重启" };

  return <section className="image-deploy" hidden={!active}>
    <div className="image-deploy-panel">
      <h3>已保存的镜像应用</h3>
      <label>选择已有应用<select value={selectedApp} disabled={selectionLocked} onChange={(event) => selectSaved(event.target.value)}><option value="">请选择已有应用</option>{savedApps.map((item) => <option key={item.application_id} value={item.application_id}>{item.name} · {states[item.deploy_state]}</option>)}</select></label>
      <button className="btn-ghost" onClick={() => setListRefresh((v) => v + 1)}>刷新应用列表</button>
      {selectedApp && <button className="btn-ghost" disabled={selectionLocked} onClick={() => selectSaved(selectedApp)}>重新读取此应用</button>}
      {selectionLocked && <p>当前页面持有未收束意图的原操作键；先核对该操作，暂不切换应用或丢弃操作键。</p>}
      {listTruncated && <p>仅显示最近 50 个应用，更早的应用未包含在此列表。</p>}
      {listError && <p role="alert">列表读取失败：{listError}</p>}
      {!listError && savedApps.length === 0 && <p>当前没有可选择的受管镜像应用。</p>}
    </div>
    <button type="button" className="btn-ghost" disabled={domainPending} onClick={() => { if (!imageDomainSelectionLocked(domainAttemptRef.current, domainCurrent)) onBack(); }}>← 返回桌面</button>
    <h2>镜像部署</h2>
    <p>公开 Docker Hub / GHCR 镜像，固定为 Linux/amd64 digest 后执行。当前应用端口仅发布到服务器本机。</p>
    {!plan && !selectedApp && <form onSubmit={createPlan} className="image-deploy-form">
      <label>应用名称<input className="webos-input" required value={appName} onChange={(e) => setAppName(e.target.value)} disabled={busy} /></label>
      <label>镜像引用<input className="webos-input" required placeholder="nginx:alpine 或 ghcr.io/组织/镜像:标签" value={image} onChange={(e) => setImage(e.target.value)} disabled={busy} /></label>
      <label>容器端口<input className="webos-input" type="number" min={1} max={65535} placeholder="如 80；留空由计划报告缺项" value={port} onChange={(e) => setPort(e.target.value)} disabled={busy} /></label>
      <label>普通环境变量（可选，每行 NAME=value）<textarea className="webos-input" rows={4} value={environment} onChange={(e) => setEnvironment(e.target.value)} disabled={busy} /></label>
      <p>此入口只接收非秘密变量，请勿填写密码或令牌。默认使用服务端资源限制，不请求特权或宿主目录挂载。</p>
      <button className="webos-btn-primary" disabled={busy}>{busy ? "正在解析镜像…" : "创建部署计划"}</button>
    </form>}
    {error && <p className="af-note af-note--error" role="alert">{error}</p>}
    {plan && <div className="image-deploy-panel">
      <h3>确认部署计划</h3>
      <dl>
        <dt>应用</dt><dd>{plan.app_name}</dd>
        <dt>固定镜像</dt><dd><code>{plan.resolved_image.repository}@{plan.resolved_image.digest}</code></dd>
        <dt>计划摘要</dt><dd><code>{plan.plan_digest}</code></dd>
        <dt>容器端口</dt><dd>{plan.canonical_input.port ?? "待补充"}</dd>
        <dt>资源限制</dt><dd>CPU {plan.canonical_input.resources.cpu_millis / 1000} 核；内存 {Math.round(plan.canonical_input.resources.memory_bytes / 1048576)} MiB；PID {plan.canonical_input.resources.pids ?? "未提供"}；磁盘预留 {plan.canonical_input.resources.disk_reservation_bytes ?? 0} 字节</dd>
        <dt>环境变量</dt><dd>{plan.canonical_input.environment?.length ? plan.canonical_input.environment.map((e) => <div key={e.name}>{e.name}={e.value}</div>) : "无"}</dd>
        <dt>命名卷</dt><dd>{plan.canonical_input.volumes?.length ? plan.canonical_input.volumes.map((v) => <div key={v.name}>{v.name} → {v.mount_path}（{v.read_only ? "只读" : "可写"}，{v.size_bytes} 字节）</div>) : "无"}</dd>
        <dt>缺少输入</dt><dd>{plan.missing_inputs.length ? plan.missing_inputs.join("、") : "无"}</dd>
      </dl>
      <p>确认将拉取固定镜像并创建受管容器，占用上述资源。应用可通过普通 NAT 出站；宿主端口由执行结果提供，只对服务器的 127.0.0.1 发布。本页不代表公网访问或 HTTPS 已就绪。</p>
      {plan.status === "needs_input" && <p role="status">请返回填写容器端口后重新创建计划。</p>}
      {!operationId && !selectedApp && <div className="image-deploy-actions">
        <button className="webos-btn-primary" disabled={busy || plan.status !== "planned"} onClick={confirm}>{busy ? "正在确认…" : confirmationAttempted ? "使用同一确认键核对 / 重试" : "确认并部署"}</button>
        {!confirmationAttempted && <button className="btn-ghost" disabled={busy} onClick={() => { setPlan(null); setError(""); }}>返回修改输入</button>}
      </div>}
      {confirmationAttempted && !operationId && !selectedApp && <p>确认键：<code>{intentKey.current}</code>。请求失败或结果未知时保留同一键；不要创建新意图重复部署。</p>}
    </div>}
    {savedCommandHistory && <div className="image-deploy-panel"><h4>上一条生命周期操作（历史记录）</h4><p>操作：<code>{savedCommandHistory.operation_id}</code>；结果：{states[savedCommandHistory.state]}。</p>{savedCommandHistory.reason && <p>{savedCommandHistory.reason}</p>}<p>此记录不代表当前运行状态；当前部署由下方重新查询的状态决定。</p></div>}
    {operationId && <div className="image-deploy-panel" aria-live="polite">
      <h3>真实部署操作</h3><p>操作 ID：<code>{operationId}</code></p>
      <p>{operation ? states[operation.state] : "正在查询操作状态…"}</p>
      {operation?.state === "failed" && <p className="af-note af-note--error">{operation.reason || "服务未提供失败原因。请保留操作 ID 供管理员核查。"}</p>}
      {operation?.action_required === true && <p className="af-note af-note--error">需要管理员处理：{operation.reason || "服务未提供具体原因，请核查已有操作。"}</p>}
      {operation?.state === "unknown" && <p>执行结果尚未确定，继续查询已有操作，不重新部署。{operation.reason && <> 原因：{operation.reason}</>}</p>}
      {operation?.result && <p>{effectiveFresh && !lifecyclePending ? "当前部署状态" : "上次部署状态（仅供参考）"}：{operation.result.status}；容器：<code>{operation.result.container_id ?? "尚未返回"}</code></p>}
      {operation?.state === "succeeded" && (endpoint ? <><p>服务器本机端点：<code>{endpoint}</code></p><p>宿主端口 {operation.result?.host_port} → 容器端口 {operation.result?.container_port}。仅能从服务器本机访问；远端浏览器不能通过这个地址访问应用。</p></> : <p>{lifecyclePending ? "生命周期操作尚未收束，暂不显示可访问地址。" : operation.result?.status === "stopped" ? "应用已停止；原容器与端口分配保留，当前没有可访问端点。" : "尚未核对到可访问地址，请查询当前部署状态。"}</p>)}
      {availableImageLifecycleActions(operation).length > 0 && <div className="image-deploy-actions" aria-label="应用启停">
        {availableImageLifecycleActions(operation).map((action) => <button key={action} className="btn-ghost" disabled={busy || lifecyclePending || domainPending || !effectiveFresh} onClick={() => beginLifecycle(action)}>{actionNames[action]}</button>)}
      </div>}
      {lifecycleAttempt && <div className="image-lifecycle-status" aria-live="polite">
        <h4>{actionNames[lifecycleAttempt.action]}操作</h4>
        <p>受管部署：<code>{lifecycleAttempt.deploymentId}</code>；容器：<code>{lifecycleAttempt.containerId}</code></p>
        <p>本次操作：<code>{lifecycleAttempt.operationId || "尚未收到操作 ID"}</code>。{lifecycleAttempt.operation ? states[lifecycleAttempt.operation.state] : "请求结果尚未确定，请使用同一操作键核对。"}</p>
        {lifecycleAttempt.operation?.state === "failed" && <p role="alert">操作失败：{lifecycleAttempt.operation.reason || "服务未提供具体原因，请保留本次操作 ID 供管理员核查。"} 核对当前部署状态后可再次操作。</p>}
        {lifecycleAttempt.operation?.state === "unknown" && lifecycleAttempt.operation.reason && <p>核对信息：{lifecycleAttempt.operation.reason}</p>}
        {lifecyclePending && lifecycleAttempt.key && <><p>操作键：<code>{lifecycleAttempt.key}</code>。继续查询或使用同一键重试；已有操作收束前不能创建新操作。</p><button className="btn-ghost" disabled={busy} onClick={() => submitLifecycle(lifecycleAttempt)}>使用同一操作键核对 / 重试</button></>}
        {lifecyclePending && !lifecycleAttempt.key && <p>已恢复已有操作的只读核对；原操作键不在当前页面，继续查询，不生成新键或重复提交。</p>}
        {lifecyclePollError && <p className="af-note af-note--error" role="alert">查询已暂停：{lifecyclePollError}。上次操作状态仅供参考。</p>}
        {lifecycleAttempt.operationId && <button className="btn-ghost" disabled={busy} onClick={() => setLifecycleRefresh((v) => v + 1)}>查询本次生命周期操作</button>}
        {!lifecyclePending && !deploymentFresh && <p>正在读取当前部署状态；未核对前不显示可访问地址或允许新动作。</p>}
      </div>}
      {pollError && <p className="af-note af-note--error" role="alert">查询已暂停：{pollError}。上次状态仅供参考。</p>}
      <button className="btn-ghost" onClick={refreshDeployment}>查询此操作</button>
      {operation && terminal(operation.state) && <button className="btn-ghost" disabled={busy || lifecyclePending || domainPending || !effectiveFresh} onClick={() => { cancelObservation(); cancelMetrics(); cancelDomainRead(); saveDomainAttempt(null); saveLifecycle(null); setLifecyclePollError(""); setSelectedApp(""); setPlan(null); setOperationId(""); setOperation(null); setConfirmationAttempted(false); setError(""); }}>开始另一次部署</button>}
      {selectedApp && domainTarget && <div className="image-domain" aria-live="polite">
        <h4>自定义域名</h4>
        <p>这里只管理此应用的本机路由。请由运营者提供已核实的公网入口目标，再自行配置 DNS；DNS 解析与外部 HTTPS 须另行检查。本页不猜测 A/CNAME 目标。</p>
        {!effectiveFresh || lifecyclePending ? <p>正在核对最新部署状态；域名操作暂不可用。</p> : domainBusy ? <p>正在读取此受管部署的域名状态…</p> : null}
        {domainError && <p className="af-note af-note--error" role="alert">域名状态未核实：{domainError}</p>}
        {domainLoaded && !domainCurrent && !domainError && <p>此应用尚无受管自定义域名。</p>}
        {domainCurrent && <>
          <p>受管域名：<code>{domainCurrent.operation.hostname}</code>；本机路由：{domainCurrent.local_route_state === "configured" ? "已配置（公网未验证）" : domainCurrent.local_route_state === "disabled" ? "已停用" : domainCurrent.local_route_state === "reconcile_required" ? "需核对" : "等待配置"}。</p>
          <p>{domainCurrent.deployment_status === "stopped" ? "应用已停止；域名配置仍保留，当前不可访问。" : domainCurrent.availability === "unverified" ? "本机路由已配置；不能据此断定 DNS 或公网 HTTPS 可用。" : domainCurrent.availability === "degraded" ? "本机路由状态需核对；不显示公网可用结论。" : "域名状态未收束；不显示公网可用结论。"}</p>
          {domainCurrent.operation.result && <p className="image-domain-observed">上次路由观测：{metricTime(domainCurrent.operation.result.observed_at)}。{domainCurrent.operation.result.certificate_fingerprint && domainCurrent.operation.result.certificate_expires_at && <>证书指纹：<code>{domainCurrent.operation.result.certificate_fingerprint}</code>；到期：{metricTime(domainCurrent.operation.result.certificate_expires_at)}。这只是已返回的证书事实，不代表当前外部 HTTPS 可访问。</>}</p>}
        </>}
        {domainAttempt && <div className="image-domain-attempt">
          <p>本次{domainAttempt.action === "ensure" ? "绑定" : "解绑"}：<code>{domainAttempt.hostname}</code>；操作：<code>{domainAttempt.operationId || "尚未收到 ID"}</code>；{domainAttempt.operation ? states[domainAttempt.operation.state] : "请求结果未知，请保留原键核对"}。</p>
          {domainAttempt.operation?.reason && <p role="alert">{domainAttempt.operation.reason}</p>}
          {imageDomainLocked(domainAttempt) && domainAttempt.key && <><p>原操作键：<code>{domainAttempt.key}</code>。只用同一域名、动作和键核对或重试；不新建第二个意图。</p><button type="button" className="btn-ghost" disabled={busy} onClick={() => submitDomain(domainAttempt)}>使用同一操作键核对 / 重试</button></>}
          {imageDomainLocked(domainAttempt) && !domainAttempt.key && <p>已从服务器只读恢复未收束操作；原键不在此页面，继续查询，不生成新键或自动重发。</p>}
          {domainAttempt.operationId && <button type="button" className="btn-ghost" onClick={() => { setDomainPollRefresh((v) => v + 1); setDomainRefresh((v) => v + 1); }}>查询域名操作</button>}
          {domainPollError && <p className="af-note af-note--error" role="alert">操作查询暂不可用：{domainPollError}</p>}
        </div>}
        {domainLoaded && !domainError && !domainPending && !lifecyclePending && effectiveFresh && <div className="image-deploy-actions">
          {(!domainCurrent || domainCurrent.local_route_state === "disabled") && operation?.result?.status === "running" && <><label>要绑定的规范小写域名<input className="webos-input" value={domainHostname} onChange={(event) => setDomainHostname(event.target.value)} placeholder={domainCurrent?.operation.hostname || "app.example.com"} disabled={busy || domainBusy} /></label><button type="button" className="btn-ghost" disabled={busy || domainBusy || !domainHostname} onClick={() => beginDomain("ensure")}>确认绑定域名</button></>}
          {domainCurrent && domainCurrent.local_route_state !== "disabled" && <button type="button" className="btn-ghost" disabled={busy || domainBusy} onClick={() => beginDomain("remove")}>解绑此受管域名</button>}
        </div>}
        <button type="button" className="btn-ghost" disabled={domainBusy} onClick={() => setDomainRefresh((v) => v + 1)}>刷新域名状态</button>
      </div>}
      {observationTarget && <div className="image-observation" aria-live="polite">
        <h4>当前容器</h4>
        {containerSample && <><p>{observationStale ? "采样已过期，请刷新" : containerSample.value.running ? "运行中" : "未运行"}</p><p className="image-observation-time">采样时间：{new Date(containerSample.value.observed_at).toLocaleString("zh-CN", { hour12: false })}。这里只读取容器状态，不检测访问地址。</p></>}
        {observationBusy && <p>正在读取真实容器数据…</p>}
        {observationError && <p className="af-note af-note--error" role="alert">容器观测暂不可用：{observationError}</p>}
        {observationCancelled && <p>已取消读取；重新刷新后才显示当前数据。</p>}
        <div className="image-deploy-actions">
          <button type="button" className="btn-ghost" disabled={observationBusy} onClick={() => void loadObservation(false, observationTarget)}>刷新容器状态</button>
          <button type="button" className="btn-ghost" disabled={observationBusy} onClick={() => void loadObservation(true, observationTarget)}>读取最近日志</button>
          {observationBusy && <button type="button" className="btn-ghost" onClick={() => cancelObservation(true)}>取消读取</button>}
        </div>
        {logSample && <><p>最近日志（最多 64 条 / 8 KiB，已脱敏）。{logSample.limited && "来源受读取范围限制。"}</p><p className="image-observation-time">读取时间：{new Date(logSample.observedAt).toLocaleString("zh-CN", { hour12: false })}；{observationStale ? "该次采样已过期，日志为历史记录。" : "内容仅代表本次有界读取。"}</p>{logSample.records.length ? <pre className="image-observation-logs">{logSample.records.map((line) => `[${line.stream === "stderr" ? "错误" : "输出"}] ${line.data}`).join("\n")}</pre> : <p>{logSample.limited ? "有界读取受限，未返回可显示记录；不能据此判断没有日志。" : "所选范围内暂无日志。"}</p>}</>}
      </div>}
      {observationTarget && <div className="image-metrics" aria-live="polite">
        <h4>当前资源指标</h4>
        <p>仅读取当前受管容器；CPU 是用量百分比，网络数值是累计字节，不代表速率或端点可访问性。</p>
        {metricsBusy && <p>正在读取资源指标与近期记录…</p>}
        {metricsError && <p className="af-note af-note--error" role="alert">指标读取暂不可用：{metricsError}</p>}
        {shownMetrics && <>
          <p className="image-metrics-time">当前采样：{metricTime(shownMetrics.current.sampled_at)}。{currentMetricsStale ? "该次当前读数已过期。" : shownMetrics.current.available ? "真实读数。" : shownMetrics.current.unavailable_reason === "not_running" ? "当前未运行。" : "当前指标不可用。"}</p>
          {shownMetrics.current.available && !currentMetricsStale && <dl className="image-metrics-values">
            <dt>CPU</dt><dd>{metricValue(shownMetrics.current.cpu_percent, "%")}；累计使用 {metricValue(shownMetrics.current.cpu_usage_millis, " ms")}</dd>
            <dt>内存</dt><dd>{memoryBytes(shownMetrics.current.memory_usage_bytes)}；容器限额 {memoryBytes(shownMetrics.current.memory_limit_bytes)}</dd>
            <dt>网络累计</dt><dd>接收 {memoryBytes(shownMetrics.current.network_rx_bytes)}；发送 {memoryBytes(shownMetrics.current.network_tx_bytes)}</dd>
            <dt>进程数</dt><dd>{metricValue(shownMetrics.current.pids_current)}</dd>
            <dt>已观测限制</dt><dd>{shownMetrics.current.limits ? `CPU ${shownMetrics.current.limits.cpu_millis} m；内存 ${memoryBytes(shownMetrics.current.limits.memory_bytes)}；PID ${shownMetrics.current.limits.pids}` : "不可用"}</dd>
          </dl>}
          <h5>近期内存趋势</h5>
          <p>{metricsError ? "本次刷新失败；以下是上次已验证的近期记录，仅供回看。" : recentMetricsStatus(shownMetrics.recent)} 服务端按受管应用数量推导过期阈值：{shownMetrics.recent.stale_after_seconds} 秒。{metricsAgeExpired && !metricsError && "此页面保留的趋势读数已过期。"}</p>
          <p className="image-metrics-time">已保留 {shownMetrics.recent.samples.length} 个样本；记录起点 {metricTime(shownMetrics.recent.history_start)}。最多保留最近 30 分钟，实际覆盖时段以图中时间为准；重启或缺失采样处断线。</p>
          <ImageMemoryTrend recent={shownMetrics.recent} />
        </>}
        <button type="button" className="btn-ghost" disabled={metricsBusy} onClick={() => void loadMetrics(observationTarget)}>刷新资源指标</button>
      </div>}
    </div>}
  </section>;
}
