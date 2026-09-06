import { useEffect, useMemo, useRef, useState } from "react";
import type { FormEvent } from "react";
import {
  createAcornFoxClient,
  AcornFoxRequestError,
  type AcornFoxClient,
  type Application,
  type DeliveryStatus,
  type PublicAccess,
  type SourceRevision,
  type Deployment,
  type LogsPage,
} from "./client";
import {
  ActionScope,
  LatestRequest,
  appendServerPage,
  keepsVisibleFacts,
  refetchAfterAccepted,
} from "./state";

type Region<T> = {
  state: "loading" | "ready" | "empty" | "unavailable" | "failed";
  value?: T;
  message?: string;
};

function ReleaseSourceLink() {
  const release = typeof __ACORNFOX_RELEASE_SOURCE__ === "undefined" ? null : __ACORNFOX_RELEASE_SOURCE__;
  if (!release) return null;
  return (
    <a className="af-source-link" href={release.url} target="_blank" rel="noopener noreferrer">
      v{release.version} · 对应源码
    </a>
  );
}

function failure(error: unknown): Region<never> {
  const request = error instanceof AcornFoxRequestError ? error : undefined;
  return {
    state: request?.kind === "unavailable" ? "unavailable" : "failed",
    message: request?.message ?? "请求未完成，请手动重试。",
  };
}
function date(value?: string): string {
  return value
    ? new Date(value).toLocaleString("zh-CN", { hour12: false })
    : "尚无记录";
}
function RegionNote({
  region,
  empty,
}: {
  region: Region<unknown>;
  empty: string;
}) {
  if (region.state === "loading")
    return (
      <p className="af-note" role="status">
        正在读取…
      </p>
    );
  if (region.state === "empty") return <p className="af-note">{empty}</p>;
  if (region.state === "unavailable")
    return <p className="af-note af-note--warn">暂不可用：{region.message}</p>;
  if (region.state === "failed")
    return <p className="af-note af-note--error">读取失败：{region.message}</p>;
  return null;
}

export function Login({
  api,
  onReady,
}: {
  api: AcornFoxClient;
  onReady: () => void;
}) {
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string>();
  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setMessage(undefined);
    try {
      await api.login(password);
      setPassword("");
      onReady();
    } catch (error) {
      setMessage(failure(error).message);
    } finally {
      setBusy(false);
    }
  }
  return (
    <main className="af-login">
      <section className="af-login__card" aria-labelledby="login-title">
        <p className="af-kicker">ACORNFOX</p>
        <h1 id="login-title">登录管理台</h1>
        <p>用管理员密码管理此机器上的应用。</p>
        <form onSubmit={submit}>
          <label>
            管理员密码
            <input
              autoFocus
              autoComplete="current-password"
              type="password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
            />
          </label>
          {message && (
            <p className="af-note af-note--error" role="alert">
              {message}
            </p>
          )}
          <button disabled={busy || password.length === 0}>
            {busy ? "正在登录…" : "登录"}
          </button>
        </form>
        <ReleaseSourceLink />
      </section>
    </main>
  );
}

export function CreateApplication({
  api,
  onCreated,
}: {
  api: AcornFoxClient;
  onCreated: (application: Application) => void;
}) {
  const [name, setName] = useState("");
  const [repository, setRepository] = useState("");
  const [ref, setRef] = useState("main");
  const [message, setMessage] = useState<string>();
  const [busy, setBusy] = useState(false);
  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setMessage(undefined);
    try {
      const result = await api.createApp({
        name,
        repositoryUrl: repository,
        ref,
      });
      setMessage("应用创建已接受，正在读取服务器记录。");
      onCreated(result.application);
      setName("");
      setRepository("");
    } catch (error) {
      setMessage(failure(error).message);
    } finally {
      setBusy(false);
    }
  }
  return (
    <form className="af-create" onSubmit={submit} aria-label="创建应用">
      <label>
        应用名称
        <input value={name} onChange={(event) => setName(event.target.value)} />
      </label>
      <label>
        公开 HTTPS Git 地址
        <input
          placeholder="https://github.com/org/project.git"
          value={repository}
          onChange={(event) => setRepository(event.target.value)}
        />
      </label>
      <label>
        版本引用
        <input value={ref} onChange={(event) => setRef(event.target.value)} />
      </label>
      <button disabled={busy || !name || !repository || !ref}>
        {busy ? "正在提交…" : "创建应用"}
      </button>
      {message && (
        <p className="af-note" role="status">
          {message}
        </p>
      )}
    </form>
  );
}

export function Applications({
  api,
  selected,
  onSelect,
}: {
  api: AcornFoxClient;
  selected?: string;
  onSelect: (value?: string) => void;
}) {
  const [region, setRegion] = useState<Region<Application[]>>({
    state: "loading",
  });
  const request = useRef(new LatestRequest());
  const refresh = async () => {
    const current = request.current.begin();
    setRegion({ state: "loading" });
    try {
      const values = await api.apps();
      if (!current()) return;
      setRegion(
        values.length
          ? { state: "ready", value: values }
          : { state: "empty", value: values },
      );
    } catch (error) {
      if (!current()) return;
      setRegion(failure(error));
    }
  };
  useEffect(() => {
    void refresh();
    return () => request.current.invalidate();
  }, []);
  const created = async (application: Application) => {
    await refresh();
    onSelect(application.id);
  };
  return (
    <aside className="af-applications" aria-label="应用">
      <header>
        <div>
          <p className="af-kicker">应用</p>
          <h2>应用列表</h2>
        </div>
        <button className="af-text-button" onClick={() => void refresh()}>
          刷新
        </button>
      </header>
      <CreateApplication api={api} onCreated={created} />
      <RegionNote
        region={region}
        empty="还没有应用。创建一个公开 Git 应用开始。"
      />
      {region.value?.map((application) => (
        <button
          className={`af-application ${selected === application.id ? "is-selected" : ""}`}
          key={application.id}
          onClick={() => onSelect(application.id)}
        >
          <strong>{application.name}</strong>
          <span>{application.id}</span>
          <small>更新于 {date(application.updated_at)}</small>
        </button>
      ))}
    </aside>
  );
}

export function Sources({
  api,
  applicationId,
  selectedId,
  onSource,
}: {
  api: AcornFoxClient;
  applicationId: string;
  selectedId?: string;
  onSource: (source?: SourceRevision) => void;
}) {
  const [region, setRegion] = useState<Region<SourceRevision[]>>({
    state: "loading",
  });
  const [detail, setDetail] = useState<Region<SourceRevision>>({
    state: "empty",
  });
  const [nextCursor, setNextCursor] = useState<string>();
  const [more, setMore] = useState<Region<never> | undefined>();
  const listRequest = useRef(new LatestRequest());
  const detailRequest = useRef(new LatestRequest());
  const chosenId = useRef<string | undefined>(selectedId);

  const select = async (candidate?: SourceRevision) => {
    chosenId.current = candidate?.id;
    const current = detailRequest.current.begin();
    onSource(undefined);
    if (!candidate) {
      if (current()) setDetail({ state: "empty" });
      return;
    }
    setDetail({ state: "loading" });
    try {
      const authoritative = await api.source(applicationId, candidate.id);
      if (!current()) return;
      setDetail({ state: "ready", value: authoritative });
      onSource(authoritative);
    } catch (error) {
      if (!current()) return;
      setDetail(failure(error));
    }
  };
  const refresh = async (
    autoSelect: boolean,
    explicit = false,
  ): Promise<SourceRevision[] | undefined> => {
    const current = listRequest.current.begin();
    const preserve = keepsVisibleFacts(region.state, explicit);
    if (preserve) setMore({ state: "loading" });
    else setRegion({ state: "loading" });
    try {
      const page = await api.sources(applicationId);
      const values = page.items;
      if (!current()) return undefined;
      setRegion(
        values.length
          ? { state: "ready", value: values }
          : { state: "empty", value: values },
      );
      setNextCursor(page.nextCursor);
      if (preserve) setMore(undefined);
      if (autoSelect && chosenId.current === undefined) void select(values[0]);
      return values;
    } catch (error) {
      if (!current()) return undefined;
      if (preserve) setMore(failure(error));
      else setRegion(failure(error));
      if (autoSelect) void select(undefined);
      return undefined;
    }
  };
  useEffect(() => {
    chosenId.current = undefined;
    void refresh(true);
    return () => {
      listRequest.current.invalidate();
      detailRequest.current.invalidate();
    };
  }, [applicationId]);
  const loadMore = async () => {
    if (!nextCursor || region.state !== "ready") return;
    const current = listRequest.current.begin();
    setMore({ state: "loading" });
    try {
      const page = await api.sources(applicationId, nextCursor);
      if (!current()) return;
      const items = [
        ...(region.value ?? []),
        ...page.items.filter(
          (item) => !region.value?.some((existing) => existing.id === item.id),
        ),
      ];
      setRegion({ state: "ready", value: items });
      setNextCursor(page.nextCursor);
      setMore(undefined);
    } catch (error) {
      if (current()) setMore(failure(error));
    }
  };
  return (
    <section className="af-section" aria-labelledby="sources-title">
      <header>
        <h2 id="sources-title">源码版本</h2>
        <button
          className="af-text-button"
          onClick={() => {
            setMore(undefined);
            void refresh(false, true);
          }}
        >
          刷新
        </button>
      </header>
      <RegionNote region={region} empty="服务器尚未发现可用源码版本。" />
      {region.value?.map((source) => (
        <button
          className={`af-row-button ${chosenId.current === source.id ? "is-selected" : ""}`}
          key={source.id}
          onClick={() => void select(source)}
        >
          <strong>{source.commit ?? source.id}</strong>
          <span>
            {source.ref ?? "未记录引用"} ·{" "}
            {source.immutable ? "不可变记录" : "等待配置"}
          </span>
        </button>
      ))}
      <RegionNote region={detail} empty="选择一个源码版本查看服务器记录。" />
      {detail.value && (
        <dl className="af-facts">
          <div>
            <dt>版本</dt>
            <dd>{detail.value.commit ?? detail.value.id}</dd>
          </div>
          <div>
            <dt>内容摘要</dt>
            <dd>{detail.value.content_digest}</dd>
          </div>
        </dl>
      )}
      {nextCursor && (
        <button
          className="af-text-button"
          onClick={() => void loadMore()}
          disabled={more?.state === "loading"}
        >
          {more?.state === "loading" ? "正在加载…" : "加载更多"}
        </button>
      )}
      {more && <RegionNote region={more} empty="" />}
    </section>
  );
}

export function Deployments({
  api,
  applicationId,
  source,
  selected,
  onSelect,
}: {
  api: AcornFoxClient;
  applicationId: string;
  source?: SourceRevision;
  selected?: Deployment;
  onSelect: (value?: Deployment) => void;
}) {
  const [region, setRegion] = useState<Region<Deployment[]>>({
    state: "loading",
  });
  const [port, setPort] = useState("");
  const [message, setMessage] = useState<string>();
  const [busy, setBusy] = useState(false);
  const [nextCursor, setNextCursor] = useState<string>();
  const [more, setMore] = useState<Region<never> | undefined>();
  const request = useRef(new LatestRequest());
  const actionScope = useRef(new ActionScope());
  const chosenId = useRef<string | undefined>(selected?.id);
  const refresh = async (
    autoSelect: boolean,
    explicit = false,
  ): Promise<Deployment[] | undefined> => {
    const current = request.current.begin();
    const preserve = keepsVisibleFacts(region.state, explicit);
    if (preserve) setMore({ state: "loading" });
    else setRegion({ state: "loading" });
    try {
      const page = await api.deployments(applicationId);
      const values = page.items;
      if (!current()) return undefined;
      setRegion(
        values.length
          ? { state: "ready", value: values }
          : { state: "empty", value: values },
      );
      setNextCursor(page.nextCursor);
      if (preserve) setMore(undefined);
      if (autoSelect && chosenId.current === undefined) {
        const next = values[0];
        chosenId.current = next?.id;
        onSelect(next);
      }
      return values;
    } catch (error) {
      if (!current()) return undefined;
      if (preserve) setMore(failure(error));
      else setRegion(failure(error));
      if (autoSelect) onSelect(undefined);
      return undefined;
    }
  };
  useEffect(() => {
    chosenId.current = undefined;
    setBusy(false);
    setMessage(undefined);
    setPort("");
    setNextCursor(undefined);
    setMore(undefined);
    void refresh(true);
    return () => {
      request.current.invalidate();
      actionScope.current.invalidate();
    };
  }, [applicationId]);
  const loadMore = async () => {
    if (!nextCursor || region.state !== "ready") return;
    const current = request.current.begin();
    setMore({ state: "loading" });
    try {
      const page = await api.deployments(applicationId, nextCursor);
      if (!current()) return;
      const items = [
        ...(region.value ?? []),
        ...page.items.filter(
          (item) => !region.value?.some((existing) => existing.id === item.id),
        ),
      ];
      setRegion({ state: "ready", value: items });
      setNextCursor(page.nextCursor);
      setMore(undefined);
    } catch (error) {
      if (current()) setMore(failure(error));
    }
  };
  async function deploy(event: FormEvent) {
    event.preventDefault();
    if (!source || busy) return;
    const ticket = actionScope.current.begin();
    if (!ticket) return;
    const scope = { applicationId, sourceId: source.id };
    setBusy(true);
    setMessage(undefined);
    try {
      const accepted = await api.deploy(
        scope.applicationId,
        scope.sourceId,
        port ? Number(port) : undefined,
      );
      if (!ticket.current()) return;
      const values = await refetchAfterAccepted(() => refresh(false, true));
      if (!ticket.current()) return;
      const created = values?.find(
        (item) => item.id === accepted.deployment_id,
      );
      if (created) {
        chosenId.current = created.id;
        onSelect(created);
        setMessage("部署已接受，正在读取服务器记录。");
      } else {
        setMessage("部署已接受，等待服务器发现部署记录。可稍后手动刷新。");
      }
    } catch (error) {
      if (ticket.current()) setMessage(failure(error).message);
    } finally {
      if (ticket.finish()) setBusy(false);
    }
  }
  return (
    <section className="af-section" aria-labelledby="deployments-title">
      <header>
        <h2 id="deployments-title">部署</h2>
        <button
          className="af-text-button"
          onClick={() => {
            setMore(undefined);
            void refresh(false, true);
          }}
        >
          刷新
        </button>
      </header>
      <form className="af-inline-form" onSubmit={deploy}>
        <label>
          容器端口（可选）
          <input
            inputMode="numeric"
            value={port}
            onChange={(event) => setPort(event.target.value)}
          />
        </label>
        <button disabled={!source || busy}>
          {busy ? "正在提交…" : "部署选中的源码"}
        </button>
      </form>
      {!source && <p className="af-note">请先等待服务器发现源码版本。</p>}
      {message && (
        <p className="af-note" role="status">
          {message}
        </p>
      )}
      <RegionNote region={region} empty="尚无部署记录。" />
      {region.value?.map((deployment) => (
        <button
          className={`af-row-button ${selected?.id === deployment.id ? "is-selected" : ""}`}
          key={deployment.id}
          onClick={() => {
            chosenId.current = deployment.id;
            onSelect(deployment);
          }}
        >
          <strong>{deployment.id}</strong>
          <span>
            {deployment.stage} · {date(deployment.updated_at)}
          </span>
        </button>
      ))}
      {nextCursor && (
        <button
          className="af-text-button"
          onClick={() => void loadMore()}
          disabled={more?.state === "loading"}
        >
          {more?.state === "loading" ? "正在加载…" : "加载更多"}
        </button>
      )}
      {more && <RegionNote region={more} empty="" />}
    </section>
  );
}

export function Logs({
  api,
  applicationId,
  deploymentId,
}: {
  api: AcornFoxClient;
  applicationId: string;
  deploymentId: string;
}) {
  const [source, setSource] = useState<"build" | "runtime">("build");
  const [region, setRegion] = useState<Region<LogsPage>>({
    state: "loading",
  });
  const [nextCursor, setNextCursor] = useState<string>();
  const [more, setMore] = useState<Region<never> | undefined>();
  const request = useRef(new LatestRequest());
  const refresh = async (replace: boolean) => {
    const current = request.current.begin();
    if (replace) setRegion({ state: "loading" });
    else setMore({ state: "loading" });
    try {
      const result = await api.logs(applicationId, deploymentId, source);
      if (!current()) return;
      setRegion(
        result.items.length
          ? { state: "ready", value: result }
          : { state: "empty", value: result },
      );
      setNextCursor(result.nextCursor);
      if (!replace) setMore(undefined);
    } catch (error) {
      if (!current()) return;
      if (replace) setRegion(failure(error));
      else setMore(failure(error));
    }
  };
  useEffect(() => {
    setNextCursor(undefined);
    setMore(undefined);
    void refresh(true);
    return () => request.current.invalidate();
  }, [applicationId, deploymentId, source]);
  const loadMore = async () => {
    if (!nextCursor || region.state !== "ready") return;
    const current = request.current.begin();
    setMore({ state: "loading" });
    try {
      const page = await api.logs(
        applicationId,
        deploymentId,
        source,
        nextCursor,
      );
      if (!current()) return;
      const items = appendServerPage(region.value?.items ?? [], page.items);
      setRegion({ state: "ready", value: { ...page, items } });
      setNextCursor(page.nextCursor);
      setMore(undefined);
    } catch (error) {
      if (current()) setMore(failure(error));
    }
  };
  return (
    <section className="af-section" aria-labelledby="logs-title">
      <header>
        <h2 id="logs-title">日志</h2>
        <span>
          <button
            className={source === "build" ? "is-selected" : ""}
            onClick={() => setSource("build")}
          >
            构建
          </button>
          <button
            className={source === "runtime" ? "is-selected" : ""}
            onClick={() => setSource("runtime")}
          >
            运行
          </button>
          <button
            className="af-text-button"
            onClick={() => {
              setMore(undefined);
              void refresh(false);
            }}
          >
            刷新
          </button>
        </span>
      </header>
      <RegionNote region={region} empty="尚未收集到日志。" />
      {region.value && (
        <>
          <p className="af-note">
            {region.value.availability === "available"
              ? "已收集记录"
              : "暂未收集"}
            {region.value.retention_limited ? "；较早记录已不再保留。" : ""}
          </p>
          <pre className="af-log">
            {region.value.items
              .map((item) => `[${date(item.recorded_at)}] ${item.content}`)
              .join("\n") || "—"}
          </pre>
        </>
      )}
      {nextCursor && (
        <button
          className="af-text-button"
          onClick={() => void loadMore()}
          disabled={more?.state === "loading"}
        >
          {more?.state === "loading" ? "正在加载…" : "加载更早"}
        </button>
      )}
      {more && <RegionNote region={more} empty="" />}
    </section>
  );
}

export function DeliveryWorkspace({
  api,
  application,
  deployment,
}: {
  api: AcornFoxClient;
  application: Application;
  deployment: Deployment;
}) {
  const [status, setStatus] = useState<Region<DeliveryStatus>>({
    state: "loading",
  });
  const [access, setAccess] = useState<Region<PublicAccess>>({
    state: "loading",
  });
  const [message, setMessage] = useState<string>();
  const [action, setAction] = useState<"restart" | "redeploy" | "probe" | "access">();
  const actionScope = useRef(new ActionScope());
  const statusRequest = useRef(new LatestRequest());
  const accessRequest = useRef(new LatestRequest());
  const refreshStatus = async () => {
    const current = statusRequest.current.begin();
    setStatus({ state: "loading" });
    try {
      const value = await api.status(application.id, deployment.id);
      if (current()) setStatus({ state: "ready", value });
    } catch (error) {
      if (current()) setStatus(failure(error));
    }
  };
  const refreshAccess = async () => {
    const current = accessRequest.current.begin();
    setAccess({ state: "loading" });
    try {
      const value = await api.publicAccess(application.id, deployment.id);
      if (current()) setAccess({ state: "ready", value });
    } catch (error) {
      if (current()) setAccess(failure(error));
    }
  };
  const refreshAll = async () => {
    await Promise.all([refreshStatus(), refreshAccess()]);
  };
  useEffect(() => {
    actionScope.current.invalidate();
    setAction(undefined);
    setMessage(undefined);
    setStatus({ state: "loading" });
    setAccess({ state: "loading" });
    void refreshAll();
    return () => {
      statusRequest.current.invalidate();
      accessRequest.current.invalidate();
      actionScope.current.invalidate();
    };
  }, [application.id, deployment.id]);
  async function command(action: "restart" | "redeploy" | "probe" | "access") {
    const ticket = actionScope.current.begin();
    if (!ticket) return;
    const scope = {
      applicationId: application.id,
      deploymentId: deployment.id,
    };
    setAction(action);
    setMessage(undefined);
    try {
      if (action === "restart")
        await api.restart(scope.applicationId, scope.deploymentId);
      else if (action === "redeploy")
        await api.redeploy(scope.applicationId, scope.deploymentId);
      else if (action === "probe")
        await api.probe(scope.applicationId, scope.deploymentId);
      else
        await api.setPublicAccess(
          scope.applicationId,
          scope.deploymentId,
          !access.value?.desired_public,
        );
      if (!ticket.current()) return;
      setMessage(
        action === "access"
          ? "公网访问设置已接受，正在读取服务器记录。"
          : action === "probe"
            ? "响应检查已接受，不代表检查完成。请查看响应记录；尚未更新时点击刷新。"
            : "操作已接受，正在读取服务器记录。",
      );
      await refetchAfterAccepted(
        action === "access" ? refreshAccess : refreshStatus,
      );
    } catch (error) {
      if (ticket.current()) setMessage(failure(error).message);
    } finally {
      if (ticket.finish()) setAction(undefined);
    }
  }
  const response = status.value?.response;
  return (
    <>
      <section className="af-section" aria-labelledby="facts-title">
        <header>
          <h2 id="facts-title">部署状态</h2>
          <button
            className="af-text-button"
            onClick={() => void refreshStatus()}
          >
            刷新
          </button>
        </header>
        <RegionNote region={status} empty="等待服务器写入部署记录。" />
        {status.value && (
          <dl className="af-facts">
            <div>
              <dt>部署阶段</dt>
              <dd>{status.value.deployment.stage}</dd>
            </div>
            <div>
              <dt>期望状态</dt>
              <dd>{status.value.desired ? "已记录" : "等待配置"}</dd>
            </div>
            <div>
              <dt>运行状态</dt>
              <dd>{status.value.runtime?.runtime_state ?? "尚未观测"}</dd>
            </div>
            <div>
              <dt>响应记录</dt>
              <dd>
                {response
                  ? `${response.outcome}${response.http_status ? ` · HTTP ${response.http_status}` : ""}`
                  : "尚未观测"}
              </dd>
            </div>
          </dl>
        )}
      </section>
      <section className="af-section" aria-labelledby="actions-title">
        <h2 id="actions-title">操作</h2>
        <div className="af-actions">
          <button
            disabled={action !== undefined}
            onClick={() => void command("probe")}
          >
            {action === "probe" ? "正在提交…" : "检查应用响应"}
          </button>
          <button
            disabled={action !== undefined}
            onClick={() => void command("restart")}
          >
            {action === "restart" ? "正在提交…" : "重启"}
          </button>
          <button
            disabled={action !== undefined}
            onClick={() => void command("redeploy")}
          >
            {action === "redeploy" ? "正在提交…" : "重新部署"}
          </button>
        </div>
        {message && (
          <p className="af-note" role="status">
            {message}
          </p>
        )}
      </section>
      <section className="af-section" aria-labelledby="access-title">
        <header>
          <h2 id="access-title">公网访问</h2>
          <button
            className="af-text-button"
            onClick={() => void refreshAccess()}
          >
            刷新
          </button>
        </header>
        <p className="af-note">
          应用运行后，先点击“检查应用响应”，确认响应记录为 responded，再开启公网访问。
          重启或重新部署后需要重新检查；运行中不等于能响应请求。
        </p>
        <RegionNote region={access} empty="尚无公网访问设置。" />
        {access.value && (
          <div className="af-access">
            <p>
              <strong>
                {access.value.desired_public
                  ? "已请求本机公网访问"
                  : "未请求本机公网访问"}
              </strong>
              <span>{access.value.url}</span>
            </p>
            <button
              disabled={action !== undefined}
              onClick={() => void command("access")}
            >
              {action === "access"
                ? "正在提交…"
                : access.value.desired_public
                  ? "关闭公网访问"
                  : "开启公网访问"}
            </button>
            <p className="af-note">
              DNS、证书和外部可达性：{access.value.components.dns} /{" "}
              {access.value.components.tls} / {access.value.components.external}
              。这些是独立事实，不代表外网已可访问。
            </p>
          </div>
        )}
      </section>
      <Logs
        api={api}
        applicationId={application.id}
        deploymentId={deployment.id}
      />
    </>
  );
}

function PasswordPanel({
  api,
  onLogout,
}: {
  api: AcornFoxClient;
  onLogout: () => void;
}) {
  const [open, setOpen] = useState(false);
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [message, setMessage] = useState<string>();
  const [changing, setChanging] = useState(false);
  const [leaving, setLeaving] = useState(false);
  async function change(event: FormEvent) {
    event.preventDefault();
    if (changing) return;
    setChanging(true);
    try {
      await api.changePassword(current, next);
      onLogout();
    } catch (error) {
      setMessage(failure(error).message);
    } finally {
      setChanging(false);
    }
  }
  return (
    <div className="af-account">
      <button onClick={() => setOpen(!open)}>账户</button>
      <button
        disabled={leaving}
        onClick={() =>
          void (async () => {
            if (leaving) return;
            setLeaving(true);
            try {
              await api.logout();
              onLogout();
            } catch (error) {
              setMessage(failure(error).message);
            } finally {
              setLeaving(false);
            }
          })()
        }
      >
        {leaving ? "正在退出…" : "退出"}
      </button>
      {open && (
        <form onSubmit={change}>
          <label>
            当前密码
            <input
              type="password"
              value={current}
              onChange={(event) => setCurrent(event.target.value)}
            />
          </label>
          <label>
            新密码
            <input
              type="password"
              value={next}
              onChange={(event) => setNext(event.target.value)}
            />
          </label>
          <button disabled={changing}>
            {changing ? "正在提交…" : "修改密码"}
          </button>
          {message && <p className="af-note af-note--error">{message}</p>}
        </form>
      )}
    </div>
  );
}

export default function AcornFoxApp({
  api: suppliedApi,
  initialAuthenticated,
}: {
  api?: AcornFoxClient;
  initialAuthenticated?: boolean;
}) {
  const [authenticated, setAuthenticated] = useState<boolean | undefined>(
    initialAuthenticated,
  );
  const [selectedApp, setSelectedApp] = useState<string>();
  const [source, setSource] = useState<SourceRevision>();
  const [deployment, setDeployment] = useState<Deployment>();
  const [application, setApplication] = useState<Application>();
  const [applicationProblem, setApplicationProblem] = useState<string>();
  const authRequest = useRef(new LatestRequest());
  const appRequest = useRef(new LatestRequest());
  const clearProtected = () => {
    appRequest.current.invalidate();
    setSelectedApp(undefined);
    setSource(undefined);
    setDeployment(undefined);
    setApplication(undefined);
    setApplicationProblem(undefined);
  };
  const api = useMemo(
    () =>
      suppliedApi ??
      createAcornFoxClient(fetch, () => {
        authRequest.current.invalidate();
        clearProtected();
        setAuthenticated(false);
      }),
    [suppliedApi],
  );
  useEffect(() => {
    const current = authRequest.current.begin();
    void api
      .session()
      .then((session) => {
        if (!current()) return;
        if (!session.authenticated) clearProtected();
        setAuthenticated(session.authenticated);
      })
      .catch(() => {
        if (!current()) return;
        clearProtected();
        setAuthenticated(false);
      });
    return () => authRequest.current.invalidate();
  }, [api]);
  const appSelected = (id?: string) => {
    const current = appRequest.current.begin();
    setSelectedApp(id);
    setSource(undefined);
    setDeployment(undefined);
    setApplication(undefined);
    setApplicationProblem(undefined);
    if (id)
      void api
        .app(id)
        .then((value) => {
          if (current()) setApplication(value);
        })
        .catch((error: unknown) => {
          if (current()) setApplicationProblem(failure(error).message);
        });
  };
  const heading = useMemo(() => application?.name ?? "选择应用", [application]);
  if (authenticated === undefined)
    return (
      <main className="af-login">
        <p role="status">正在检查登录状态…</p>
      </main>
    );
  if (!authenticated)
    return (
      <Login
        api={api}
        onReady={() => {
          clearProtected();
          setAuthenticated(true);
        }}
      />
    );
  return (
    <main className="af-shell">
      <header className="af-topbar">
        <a className="af-brand" href="/">
          AcornFox
        </a>
        <ReleaseSourceLink />
        <PasswordPanel
          api={api}
          onLogout={() => {
            authRequest.current.invalidate();
            clearProtected();
            setAuthenticated(false);
          }}
        />
      </header>
      <div className="af-layout">
        <Applications api={api} selected={selectedApp} onSelect={appSelected} />
        <section className="af-workspace" aria-label="应用工作区">
          <header className="af-workspace__header">
            <p className="af-kicker">应用工作区</p>
            <h1>{heading}</h1>
            <p>
              服务器记录决定这里显示的事实。操作被接受后只读取一次最新记录。
            </p>
          </header>
          {!selectedApp && (
            <div className="af-empty">
              从左侧选择应用，或创建一个公开 HTTPS Git 应用。
            </div>
          )}
          {selectedApp && !application && !applicationProblem && (
            <p role="status">正在读取应用…</p>
          )}
          {applicationProblem && (
            <p className="af-note af-note--error" role="alert">
              读取应用失败：{applicationProblem}
            </p>
          )}
          {application && (
            <>
              <Sources
                api={api}
                applicationId={application.id}
                selectedId={source?.id}
                onSource={setSource}
              />
              <Deployments
                api={api}
                applicationId={application.id}
                source={source}
                selected={deployment}
                onSelect={setDeployment}
              />
              {deployment && (
                <DeliveryWorkspace
                  api={api}
                  application={application}
                  deployment={deployment}
                />
              )}
              {!deployment && (
                <div className="af-empty">
                  选择部署后可以查看状态、日志和公网访问记录。
                </div>
              )}
            </>
          )}
        </section>
      </div>
    </main>
  );
}
