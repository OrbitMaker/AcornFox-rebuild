import { useEffect, useMemo, useRef, useState } from "react";
import { AcornFoxRequestError, createAcornFoxClient, type AcornFoxClient, type Command, type SourceRevision } from "./client";
import { candidatePublishKey, createFixCandidateClient, type FixCandidate, type FixCandidateClient, type ValidatedFixCandidate } from "./fix-candidate-client";
import { pollFixCandidates } from "./fix-candidate-polling";
import "./fix-candidates.css";

const short = (value: string) => value.slice(0, 12);
export function candidateIsCurrent(candidate: FixCandidate, now = Date.now()): candidate is ValidatedFixCandidate {
  return (candidate.status === "validated" || candidate.status === "source_matched") && Date.parse(candidate.expires_at) > now;
}
function errorMessage(error: unknown): string {
  if (error instanceof AcornFoxRequestError) {
    if (error.status === 401) return "登录已过期，请重新登录。";
    if (error.code === "fix_candidate_source_mismatch") return "源码与候选内容不一致，请核对仓库和提交后重新导入。";
    if (error.status === 409) return "候选状态已变化或已到期，请刷新事实。";
  }
  return "候选事实暂时无法读取，请刷新重试。";
}

export function CandidateEvidence({ candidate }: { candidate: ValidatedFixCandidate }) {
  return <div className="af-fix__evidence">
    <dl><dt>基础提交</dt><dd><code title={candidate.base_commit}>{short(candidate.base_commit)}</code></dd><dt>构建</dt><dd>已验证 <code title={candidate.validated_image.digest}>{short(candidate.validated_image.digest.slice(7))}</code></dd><dt>试运行</dt><dd>已响应{candidate.runtime.http_status === undefined ? "" : ` · HTTP ${candidate.runtime.http_status}`}</dd><dt>清理</dt><dd>临时容器已停止并清理</dd></dl>
    <details><summary>查看修改 · {candidate.changed_paths.length} 个文件</summary><ul>{candidate.changed_paths.map((path) => <li key={path}><code>{path}</code></li>)}</ul><pre tabIndex={0} aria-label="候选修改差异">{candidate.canonical_diff}</pre></details>
  </div>;
}

function CandidateCard({ candidate, appName, client, sourceClient, refresh }: { candidate: FixCandidate; appName: string; client: FixCandidateClient; sourceClient: AcornFoxClient; refresh: () => void }) {
  const [expanded, setExpanded] = useState(false), [sources, setSources] = useState<SourceRevision[]>([]), [cursor, setCursor] = useState<string>(), [sourcesLoaded, setSourcesLoaded] = useState(false), [selectedSource, setSelectedSource] = useState(""), [busy, setBusy] = useState(false), [message, setMessage] = useState<string>(), [confirm, setConfirm] = useState(false), [result, setResult] = useState<Command>(), [unknown, setUnknown] = useState(false), [now, setNow] = useState(Date.now());
  const inFlight = useRef(false);
  const eligible = candidateIsCurrent(candidate, now);
  useEffect(() => { if (candidate.status !== "validated" && candidate.status !== "source_matched") return; const remaining = Date.parse(candidate.expires_at) - Date.now(); if (remaining <= 0) { setNow(Date.now()); return; } const timer = setTimeout(() => setNow(Date.now()), Math.min(remaining + 1, 2_147_483_647)); return () => clearTimeout(timer); }, [candidate]);
  const loadSources = async (more = false) => {
    if (inFlight.current) return; inFlight.current = true; setBusy(true); setMessage(undefined);
    try { const page = await sourceClient.sources(candidate.application_id, more ? cursor : undefined); const available = page.items.filter((source) => source.application_id === candidate.application_id && source.immutable && source.kind === "git_https" && source.commit); setSources((previous) => more ? [...new Map([...previous, ...available].map((source) => [source.id, source])).values()] : available); setCursor(page.nextCursor); setSourcesLoaded(true); if (!more) setSelectedSource((previous) => available.some((source) => source.id === previous) ? previous : ""); }
    catch (error) { setMessage(errorMessage(error)); }
    finally { inFlight.current = false; setBusy(false); }
  };
  const match = async () => {
    if (inFlight.current || !selectedSource || !eligible || candidate.status !== "validated") return;
    inFlight.current = true; setBusy(true); setMessage(undefined);
    try { await client.match(candidate.application_id, candidate.candidate_id, selectedSource); setMessage("已校对导入源码，请核对提交后确认发布。"); refresh(); }
    catch (error) { setMessage(errorMessage(error)); refresh(); }
    finally { inFlight.current = false; setBusy(false); }
  };
  const publish = async (recoverExisting = false) => {
    if (inFlight.current || result || candidate.status !== "source_matched" || (!recoverExisting && !unknown && (!eligible || !confirm))) return;
    inFlight.current = true; setBusy(true); setMessage(undefined);
    try { const command = await client.publish(candidate.application_id, candidate.candidate_id, candidatePublishKey(candidate.application_id, candidate.candidate_id)); setResult(command); setUnknown(false); setConfirm(false); }
    catch (error) { if (error instanceof AcornFoxRequestError && error.status !== undefined && error.status >= 400 && error.status < 500) { setUnknown(false); setConfirm(false); setMessage(errorMessage(error)); refresh(); } else { setUnknown(true); setMessage("发布结果尚未确认。重试会核对并继续同一次发布。"); } }
    finally { inFlight.current = false; setBusy(false); }
  };
  const label = ({ preparing: "验证中", failed: "验证失败", validated: "已验证 · 待校对源码", source_matched: "源码已校对" })[candidate.status];
  return <article className="af-fix__card">
    <button className="af-fix__row" aria-expanded={expanded} onClick={() => setExpanded((value) => !value)}><span>候选 {short(candidate.candidate_id.slice(10))}</span><span>{result ? "发布已受理" : label} {expanded ? "−" : "+"}</span></button>
    {expanded && <div className="af-fix__content">
      {candidate.status === "preparing" && <p>正在构建、试运行并核对清理结果，完成后才能继续。</p>}
      {candidate.status === "failed" && <p>本次验证未通过，不能发布。可让助手根据失败事实创建新的修复候选。</p>}
      {(candidate.status === "validated" || candidate.status === "source_matched") && <>
        <CandidateEvidence candidate={candidate} />
        {!eligible && !result && <p role="status">候选已到期，需重新生成并验证。</p>}
        {candidate.status === "validated" && eligible && <div className="af-fix__match"><p>先把修改提交到原仓库并在源码页导入，再选择该版本校对。</p><div className="af-fix__controls"><button onClick={() => void loadSources()} disabled={busy}>读取已导入版本</button>{cursor && <button onClick={() => void loadSources(true)} disabled={busy}>更多版本</button>}</div>{sourcesLoaded && !sources.length && <p>暂无可校对的已导入提交，请先到源码页导入。</p>}{sources.length > 0 && <><select aria-label={`候选 ${short(candidate.candidate_id.slice(10))} 的导入源码`} value={selectedSource} disabled={busy} onChange={(event) => setSelectedSource(event.target.value)}><option value="">选择已导入的提交</option>{sources.map((source) => <option key={source.id} value={source.id}>{short(source.commit ?? "")} · {source.ref ?? source.id}</option>)}</select><button onClick={() => void match()} disabled={busy || !selectedSource}>校对源码内容</button></>}</div>}
        {candidate.status === "source_matched" && <div className="af-fix__publish"><p>已校对提交 <code title={candidate.matched_commit}>{short(candidate.matched_commit ?? "")}</code> · 端口 {candidate.container_port}</p>{!result && !eligible && !unknown && <button disabled={busy} onClick={() => void publish(true)}>核对既有发布</button>}{!result && (eligible || unknown) && <>{unknown ? <button disabled={busy} onClick={() => void publish()}>核对并继续原发布</button> : confirm ? <div role="group" aria-label="确认候选发布"><p>将为「{appName}」发布这个已校对的提交；如已提交过，会返回原部署。确认继续？</p><div className="af-fix__controls"><button disabled={busy} onClick={() => void publish()}>确认发布</button><button disabled={busy} onClick={() => setConfirm(false)}>取消</button></div></div> : <button onClick={() => setConfirm(true)}>发布已校对版本</button>}</>}</div>}
      </>}
      {result && <div role="status"><p>发布已受理，运行结果请到部署页核对。</p><dl><dt>部署</dt><dd><code>{result.deployment_id}</code></dd><dt>操作</dt><dd><code>{result.operation_id}</code></dd></dl></div>}
      {message && <p role="status">{message}</p>}
    </div>}
  </article>;
}

export function FixCandidates({ appId, appName, running, refreshKey, client: suppliedClient, sourceClient: suppliedSourceClient }: { appId: string; appName?: string; running: boolean; refreshKey: string; client?: FixCandidateClient; sourceClient?: AcornFoxClient }) {
  const client = useMemo(() => suppliedClient ?? createFixCandidateClient(), [suppliedClient]);
  const sourceClient = useMemo(() => suppliedSourceClient ?? createAcornFoxClient(), [suppliedSourceClient]);
  const [items, setItems] = useState<FixCandidate[]>([]), [message, setMessage] = useState<string>(), [refreshCount, setRefreshCount] = useState(0), [loaded, setLoaded] = useState(false);
  useEffect(() => {
    setMessage(undefined);
    return pollFixCandidates({ read: () => client.list(appId), receive: (values) => { setItems(values); setLoaded(true); setMessage(undefined); }, fail: (error) => setMessage(errorMessage(error)), exhausted: () => setMessage("自动刷新已暂停，可手动刷新验证进度。"), running });
  }, [appId, client, running, refreshKey, refreshCount]);
  const refresh = () => setRefreshCount((value) => value + 1);
  return <section className="af-fix" aria-label={`应用 ${appName ?? appId} 的修复候选`}><div className="af-fix__heading"><strong title={appName ?? appId}>修复候选 · {appName ?? short(appId)}</strong><button onClick={refresh} aria-label="刷新修复候选">刷新</button></div>{message && <p role="status">{message}</p>}{loaded && !items.length && <p>暂无候选。助手完成修复验证后，会在这里显示。</p>}{items.map((candidate) => <CandidateCard key={candidate.candidate_id} candidate={candidate} appName={appName ?? appId} client={client} sourceClient={sourceClient} refresh={refresh} />)}</section>;
}
