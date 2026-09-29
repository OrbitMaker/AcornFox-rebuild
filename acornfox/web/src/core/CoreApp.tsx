import { useEffect, useMemo, useRef, useState } from "react";
import { Login } from "../shared/Login";
import { Setup } from "../shared/Setup";
import { Account } from "../shared/Account";
import { CoreHelp } from "./CoreHelp";
import { MenuBar } from "../shared/MenuBar";
import { Toast } from "../shared/Toast";
import { useDesktopPresentation } from "../shared/useDesktopPresentation";
import { ImageDeployView } from "./ImageDeployView";
import { HostMetricsView } from "./HostMetricsView";
import {
  createCoreAuthClient,
  type CoreAuthClient,
  type CoreStatus,
  type SetupState,
  type HostMetricsResponse,
  AcornFoxRequestError,
} from "../shared/auth-transport";

export interface CoreAppProps {
  api?: CoreAuthClient;
  initialAuthenticated?: boolean;
}

type CoreView = "home" | "account" | "status" | "metrics" | "image";

type Region<T> = {
  state: "loading" | "ready" | "failed" | "unavailable";
  value?: T;
  message?: string;
};

export default function CoreApp({
  api: suppliedApi,
  initialAuthenticated,
}: CoreAppProps) {
  const [authenticated, setAuthenticated] = useState<boolean | undefined>(
    initialAuthenticated,
  );
  const [setup, setSetup] = useState<Region<SetupState>>({ state: "loading" });
  const [coreStatus, setCoreStatus] = useState<Region<CoreStatus>>({
    state: "loading",
  });
  const [metricsSnapshot, setMetricsSnapshot] = useState<HostMetricsResponse | null>(null);
  const [metricsPoints, setMetricsPoints] = useState<HostMetricsResponse[]>([]);
  const [metricsLoading, setMetricsLoading] = useState(false);
  const [metricsError, setMetricsError] = useState<string | undefined>(undefined);
  const [metricsStale, setMetricsStale] = useState(false);

  const metricsEpochRef = useRef(0);
  const abortControllerRef = useRef<AbortController | null>(null);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const [page, setPage] = useState<CoreView>("home");
  const [controlCenterOpen, setControlCenterOpen] = useState(false);
  const [capabilitiesModalOpen, setCapabilitiesModalOpen] = useState(false);
  const [helpOpen, setHelpOpen] = useState(false);
  const { theme, toggleThemeMode, clock, toast, showToast } =
    useDesktopPresentation();

  const authRef = useRef(0);
  const api = useMemo(
    () =>
      suppliedApi ??
      createCoreAuthClient(fetch, () => {
        setAuthenticated(false);
      }),
    [suppliedApi],
  );

  const stopMetrics = () => {
    metricsEpochRef.current += 1;
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
      abortControllerRef.current = null;
    }
    if (timerRef.current) {
      clearTimeout(timerRef.current);
      timerRef.current = null;
    }
    setMetricsLoading(false);
  };

  const fetchMetrics = async (force = false) => {
    if (!force && abortControllerRef.current) {
      return;
    }

    stopMetrics();

    if (
      authenticated !== true ||
      page !== "metrics" ||
      (typeof document !== "undefined" && document.visibilityState === "hidden")
    ) {
      return;
    }

    const controller = new AbortController();
    abortControllerRef.current = controller;
    const epoch = metricsEpochRef.current;
    setMetricsLoading(true);

    let wasExternalAbort = false;
    try {
      const [snap, recent] = await Promise.all([
        api.hostMetrics(controller.signal),
        api.hostMetricsRecent(360, controller.signal),
      ]);
      if (epoch === metricsEpochRef.current && !controller.signal.aborted) {
        setMetricsSnapshot(snap);
        setMetricsPoints(recent.points);
        setMetricsError(undefined);
        let stale = snap.availability === "unavailable";
        if (snap.observed_at) {
          const obsMs = new Date(snap.observed_at).getTime();
          if (!Number.isNaN(obsMs) && Date.now() - obsMs > snap.stale_after_seconds * 1000) {
            stale = true;
          }
        }
        setMetricsStale(stale);
      }
    } catch (err: unknown) {
      const isOriginalAbort =
        controller.signal.aborted ||
        (err as Error)?.name === "AbortError" ||
        epoch !== metricsEpochRef.current;
      wasExternalAbort = isOriginalAbort;

      controller.abort();

      if (isOriginalAbort) {
        return;
      }
      if (epoch === metricsEpochRef.current) {
        const msg =
          err instanceof AcornFoxRequestError ? err.message : "读取宿主机器指标失败";
        setMetricsError(msg);
        setMetricsStale(true);
      }
    } finally {
      if (epoch === metricsEpochRef.current) {
        setMetricsLoading(false);
        abortControllerRef.current = null;
        if (
          !wasExternalAbort &&
          authenticated === true &&
          page === "metrics" &&
          typeof document !== "undefined" &&
          document.visibilityState !== "hidden"
        ) {
          timerRef.current = setTimeout(() => {
            void fetchMetrics();
          }, 5000);
        }
      }
    }
  };

  useEffect(() => {
    if (authenticated === true && page === "metrics") {
      void fetchMetrics(true);
    } else {
      stopMetrics();
    }
    return () => {
      stopMetrics();
    };
  }, [authenticated, page, api]);

  useEffect(() => {
    const handleVisibility = () => {
      if (typeof document === "undefined") return;
      if (document.visibilityState === "hidden") {
        stopMetrics();
      } else if (authenticated === true && page === "metrics") {
        void fetchMetrics(true);
      }
    };
    if (typeof document !== "undefined") {
      document.addEventListener("visibilitychange", handleVisibility);
      return () => {
        document.removeEventListener("visibilitychange", handleVisibility);
      };
    }
  }, [authenticated, page, api]);

  // Check auth session
  useEffect(() => {
    const epoch = ++authRef.current;
    if (initialAuthenticated !== undefined) return;
    void api
      .session()
      .then((session) => {
        if (epoch === authRef.current) setAuthenticated(session.authenticated);
      })
      .catch(() => {
        if (epoch === authRef.current) setAuthenticated(false);
      });
  }, [api, initialAuthenticated]);

  // When unauthenticated, check setup state using consistent transition
  const checkSetupState = async () => {
    setSetup({ state: "loading" });
    try {
      const state = await api.setupState();
      if (state === "unavailable") {
        setSetup({
          state: "unavailable",
          value: "unavailable",
          message: "初始化服务暂不可用，请稍后重试。",
        });
      } else {
        setSetup({
          state: "ready",
          value: state,
        });
      }
    } catch (error: unknown) {
      const msg =
        error instanceof AcornFoxRequestError
          ? error.message
          : "无法获取初始化状态，请刷新重试。";
      setSetup({ state: "failed", message: msg });
    }
  };

  useEffect(() => {
    if (authenticated !== false) return;
    void checkSetupState();
  }, [authenticated, api]);

  // Load core status when authenticated
  const loadCoreStatus = async () => {
    setCoreStatus({ state: "loading" });
    try {
      const status = await api.coreStatus();
      setCoreStatus({ state: "ready", value: status });
    } catch (error) {
      const msg =
        error instanceof AcornFoxRequestError
          ? error.message
          : "读取核心状态失败，请检查服务后重试。";
      setCoreStatus({ state: "failed", message: msg });
    }
  };

  useEffect(() => {
    if (authenticated === true) {
      void loadCoreStatus();
    }
  }, [authenticated, api]);

  const logout = () => {
    authRef.current += 1;
    stopMetrics();
    setMetricsSnapshot(null);
    setMetricsPoints([]);
    setPage("home");
    setControlCenterOpen(false);
    setAuthenticated(false);
  };

  if (authenticated === undefined) {
    return (
      <main className="webos-login-wrap">
        <p className="af-note" role="status">正在检查登录状态…</p>
      </main>
    );
  }

  if (!authenticated) {
    if (setup.state === "loading") {
      return (
        <main className="webos-login-wrap">
          <p className="af-note" role="status">正在读取初始化状态…</p>
        </main>
      );
    }
    if (setup.state === "unavailable" || setup.value === "unavailable" || setup.state === "failed") {
      const isUnavailable = setup.state === "unavailable" || setup.value === "unavailable";
      return (
        <main className="webos-login-wrap">
          <section className="webos-login-card">
            <h1 style={{ fontSize: 18, color: "var(--text-main)", marginBottom: 12 }}>
              {isUnavailable ? "服务暂不可用" : "初始化状态异常"}
            </h1>
            <p className={isUnavailable ? "af-note af-note--warn" : "af-note af-note--error"} role="alert">
              {setup.message ?? (isUnavailable ? "初始化服务暂不可用，请稍后重试。" : "无法获取初始化状态。")}
            </p>
            <button
              className="webos-btn-primary"
              style={{ width: "100%", marginTop: 12 }}
              onClick={() => void checkSetupState()}
            >
              重试连接
            </button>
          </section>
        </main>
      );
    }

    // When uninitialized: run setup. On completion, transition to Login (setup alone is not login)
    return setup.value === "uninitialized" ? (
      <Setup
        api={api}
        onReady={() => {
          showToast("管理员账号初始化成功，请登录");
          setSetup({ state: "ready", value: "initialized" });
        }}
      />
    ) : (
      <Login api={api} onReady={() => setAuthenticated(true)} />
    );
  }

  const statusReady = coreStatus.state === "ready";
  const statusFailed = coreStatus.state === "failed";
  const statusLoading = coreStatus.state === "loading";
  const statusVal = coreStatus.value;

  return (
    <div className="app-viewport">
      {/* 顶部极简 macOS 菜单栏 */}
      <MenuBar
        brandTitle="AcornFox"
        onBrandClick={() => setPage("home")}
        menuItems={
          <>
            <button
              className={`menu-item-link ${page === "home" ? "is-active" : ""}`}
              onClick={() => setPage("home")}
            >
              首页
            </button>
            <button
              className={`menu-item-link ${page === "status" ? "is-active" : ""}`}
              onClick={() => setPage("status")}
            >
              核心状态
            </button>
            <button
              className={`menu-item-link ${page === "metrics" ? "is-active" : ""}`}
              onClick={() => setPage("metrics")}
            >
              机器指标
            </button>
            <button className={`menu-item-link ${page === "image" ? "is-active" : ""}`} onClick={() => setPage("image")}>镜像部署</button>
            <button
              className={`menu-item-link ${controlCenterOpen ? "is-active" : ""}`}
              onClick={() => setControlCenterOpen((v) => !v)}
            >
              控制中心
            </button>
          </>
        }
        statusBadge={
          <>
            <div
              className={`tray-badge-dot ${statusFailed ? "is-error" : statusLoading ? "is-warn" : ""}`}
              title={
                statusReady
                  ? "SQLite 核心已就绪"
                  : statusFailed
                    ? "核心状态异常"
                    : "正在检查核心…"
              }
            />
            <span className="tray-status-label">
              {statusReady ? "SQLite 核心" : statusFailed ? "核心异常" : "检查中…"}
            </span>
          </>
        }
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
          <span>AcornFox 控制中心</span>
          <span className={`cc-status-pill ${statusFailed ? "is-error" : statusLoading ? "is-warn" : ""}`}>
            {statusReady ? "● SQLite 就绪" : statusFailed ? "● 获取失败" : "● 连接中"}
          </span>
        </div>
        <div className="cc-tile-row">
          <div className="cc-tile">
            <div className="cc-tile-icon">
              <svg viewBox="0 0 24 24"><ellipse cx="12" cy="5" rx="9" ry="3" /><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3" /><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5" /></svg>
            </div>
            <div className="cc-tile-name">数据存储</div>
            <div className="cc-tile-sub">
              {statusReady ? (statusVal?.storage === "sqlite" ? "SQLite 单机模式" : statusVal?.storage) : "—"}
            </div>
          </div>
          <div className="cc-tile">
            <div className="cc-tile-icon">
              <svg viewBox="0 0 24 24"><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z" /></svg>
            </div>
            <div className="cc-tile-name">执行器</div>
            <div className="cc-tile-sub">
              {statusReady && statusVal ? (statusVal.executor.container ? "已连接" : "未连接") : "—"}
            </div>
          </div>
        </div>

        <div className="cc-info-box">
          <p style={{ marginBottom: 6 }}><strong>单机运行模式：</strong></p>
          <p>执行器连接：{statusVal ? executorSummary(statusVal) : "—"}。可通过镜像部署入口创建计划并查询真实部署结果。</p>
        </div>

        {statusFailed && (
          <div style={{ marginBottom: 12 }}>
            <p className="af-note af-note--error" role="alert" style={{ fontSize: 11, marginBottom: 8 }}>
              {coreStatus.message}
            </p>
            <button className="btn-ghost" style={{ width: "100%", padding: "6px 0", fontSize: 12 }} onClick={loadCoreStatus}>
              重试连接核心状态
            </button>
          </div>
        )}

        <div className="cc-footer-action">
          <span>外观: {theme === "dark" ? "暗黑模式" : "浅色明亮"}</span>
          <button className="cc-btn-link" onClick={() => { setPage("home"); void api.logout().then(logout).catch(() => undefined); }}>
            退出登录
          </button>
        </div>
      </div>

      {/* 主舞台视口 */}
      <div className="stage" onClick={() => controlCenterOpen && setControlCenterOpen(false)}>
        <ImageDeployView api={api} active={page === "image"} onBack={() => setPage("home")} onAuthenticationFailure={logout} />
        {/* 视图 1: 沉浸大图标桌面 */}
        {page === "home" && (
          <main className="desktop-view" id="desktopView">
            <div className="app-grid-container">
              <div className="app-grid">
                {/* 1. 核心状态 */}
                <button
                  className="app-card-btn"
                  onClick={() => setPage("status")}
                  title="查看核心运行状态与存储事实"
                >
                  <div className="app-icon-squircle">
                    <svg viewBox="0 0 24 24"><ellipse cx="12" cy="5" rx="9" ry="3" /><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3" /><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5" /></svg>
                  </div>
                  <div className="app-name-text">核心状态</div>
                  <div className={`app-status-badge ${statusReady ? "badge-ok" : statusFailed ? "badge-error" : "badge-unknown"}`}>
                    {statusReady ? "● SQLite 存储" : statusFailed ? "● 状态异常" : "● 读取中"}
                  </div>
                </button>

                {/* 2. 机器指标 */}
                <button
                  className="app-card-btn"
                  onClick={() => setPage("metrics")}
                  title="查看宿主机器真实硬件指标采样与近30分钟趋势"
                >
                  <div className="app-icon-squircle">
                    <svg viewBox="0 0 24 24"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12" /></svg>
                  </div>
                  <div className="app-name-text">机器指标</div>
                  <div className="app-status-badge badge-ok">
                    ● 原生采样
                  </div>
                </button>

                <button className="app-card-btn" onClick={() => setPage("image")} title="创建固定镜像计划并确认部署">
                  <div className="app-icon-squircle"><svg viewBox="0 0 24 24"><path d="M3 7l9-5 9 5v10l-9 5-9-5V7z" /><path d="M3 7l9 5 9-5M12 12v10" /></svg></div>
                  <div className="app-name-text">镜像部署</div><div className="app-status-badge badge-unknown">计划 → 确认 → 操作结果</div>
                </button>
                {/* 3. 发行说明 */}
                <button
                  className="app-card-btn"
                  onClick={() => setCapabilitiesModalOpen(true)}
                  title="统一发行说明"
                >
                  <div className="app-icon-squircle">
                    <svg viewBox="0 0 24 24"><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z" /><polyline points="3.27 6.96 12 12.01 20.73 6.96" /><line x1="12" y1="22.08" x2="12" y2="12" /></svg>
                  </div>
                  <div className="app-name-text">发行说明</div>
                  <div className="app-status-badge badge-unknown">● 统一发行</div>
                </button>

                {/* 3. 外部 AI 帮助 */}
                <button
                  className="app-card-btn"
                  onClick={() => setHelpOpen(true)}
                  title="外部 AI 协作指南与核心 CLI"
                >
                  <div className="app-icon-squircle">
                    <svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10" /><path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3" /><line x1="12" y1="17" x2="12.01" y2="17" /></svg>
                  </div>
                  <div className="app-name-text">外部 AI 帮助</div>
                  <div className="app-status-badge badge-ok">● 命令行协作</div>
                </button>

                {/* 4. 账户设置 */}
                <button
                  className="app-card-btn"
                  onClick={() => setPage("account")}
                  title="管理员密码修改"
                >
                  <div className="app-icon-squircle">
                    <svg viewBox="0 0 24 24"><rect width="18" height="18" x="3" y="3" rx="2" /><path d="m9 12 2 2 4-4" /></svg>
                  </div>
                  <div className="app-name-text">账户设置</div>
                  <div className="app-status-badge badge-ok">● 管理员凭据</div>
                </button>
              </div>

              <div style={{ marginTop: 10, textAlign: "center" }}>
                <p className="af-footnote">
                  AcornFox 单机控制面 · SQLite 持久化管理事实。
                </p>
                <p className="af-footnote">
                  镜像部署需先确认固定计划；当前应用端点仅对服务器本机开放。
                </p>
              </div>
            </div>

            {/* 底部悬浮胶囊 Dock 栏 */}
            <div className="floating-dock">
              <button
                className="dock-btn is-active"
                onClick={() => setPage("home")}
              >
                <svg viewBox="0 0 24 24"><path d="m3 9 9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z" /></svg>
                <span>桌面</span>
              </button>
              <button
                className="dock-btn"
                onClick={() => setPage("status")}
              >
                <svg viewBox="0 0 24 24"><ellipse cx="12" cy="5" rx="9" ry="3" /><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3" /><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5" /></svg>
                <span>核心状态</span>
              </button>
              <button
                className="dock-btn"
                onClick={() => setPage("metrics")}
                title="机器指标"
              >
                <svg viewBox="0 0 24 24"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12" /></svg>
                <span>机器指标</span>
              </button>
              <button
                className="dock-btn"
                onClick={() => setHelpOpen(true)}
              >
                <svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10" /><path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3" /><line x1="12" y1="17" x2="12.01" y2="17" /></svg>
                <span>外部 AI 帮助</span>
              </button>
              <div className="dock-separator" />
              <button
                className="dock-btn"
                onClick={() => setPage("account")}
              >
                <svg viewBox="0 0 24 24"><path d="M19 21v-2a4 4 0 0 0-4-4H9a4 4 0 0 0-4 4v2" /><circle cx="12" cy="7" r="4" /></svg>
                <span>账户</span>
              </button>
            </div>
          </main>
        )}

        {/* 视图 2: 核心状态详情 */}
        {page === "status" && (
          <section className="af-form-page" style={{ maxWidth: 560, margin: "40px auto", padding: "0 20px" }}>
            <header style={{ marginBottom: 24 }}>
              <button
                type="button"
                className="btn-ghost"
                style={{ marginBottom: 12, padding: "4px 10px", fontSize: 13 }}
                onClick={() => setPage("home")}
              >
                ← 返回桌面
              </button>
              <h2 style={{ fontSize: 20, fontWeight: 600, color: "var(--text-main)" }}>核心运行状态</h2>
              <p style={{ fontSize: 13, color: "var(--text-muted)", marginTop: 4 }}>
                SQLite 单机控制面状态与能力声明
              </p>
            </header>

            {statusLoading && <p className="af-note" role="status">正在读取核心状态…</p>}
            {statusFailed && (
              <div style={{ marginBottom: 16 }}>
                <p className="af-note af-note--error" role="alert">读取失败：{coreStatus.message}</p>
                <button
                  type="button"
                  className="btn-white"
                  style={{ marginTop: 8 }}
                  onClick={loadCoreStatus}
                >
                  重试连接
                </button>
              </div>
            )}

            {statusReady && statusVal && (
              <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
                <div className="webos-form-field">
                  <label>存储驱动</label>
                  <input
                    type="text"
                    readOnly
                    className="webos-input"
                    value={statusVal.storage === "sqlite" ? "SQLite（单机持久化控制面）" : statusVal.storage}
                  />
                </div>
                {([
                  ["容器运行", statusVal.executor.container],
                  ["源码构建", statusVal.executor.source_build],
                  ["域名与 HTTPS", statusVal.executor.gateway],
                ] as const).map(([label, ok]) => (
                  <div className="webos-form-field" key={label}>
                    <label>{label}</label>
                    <input type="text" readOnly className="webos-input" value={ok ? "已连接" : "未连接"} />
                  </div>
                ))}
                <div className="cc-info-box" style={{ marginTop: 8 }}>
                  <p><strong>说明：</strong>此页面展示服务端核心状态。镜像部署入口单独查询部署计划和操作结果；核心状态不能替代组件健康或应用访问验收。</p>
                </div>
              </div>
            )}
          </section>
        )}

        {/* 视图 3: 账户设置 */}
        {page === "account" && (
          <Account api={api} onLogout={logout} onBack={() => setPage("home")} />
        )}

        {/* 视图 4: 机器监控指标 */}
        {page === "metrics" && (
          <div style={{ width: "100%", maxWidth: 960, margin: "20px auto 40px", padding: "0 16px", boxSizing: "border-box" }}>
            <button
              type="button"
              className="btn-ghost"
              style={{ marginBottom: 12, padding: "4px 10px", fontSize: 13 }}
              onClick={() => setPage("home")}
            >
              ← 返回桌面
            </button>
            <HostMetricsView
              snapshot={metricsSnapshot}
              points={metricsPoints}
              loading={metricsLoading}
              error={metricsError}
              stale={metricsStale}
              onRefresh={() => void fetchMetrics(true)}
            />
          </div>
        )}
      </div>

      {/* 功能包说明弹窗 */}
      {capabilitiesModalOpen && (
        <div className="external-ai-help-overlay">
          <div className="external-ai-help-backdrop" onClick={() => setCapabilitiesModalOpen(false)} />
          <div className="external-ai-help-dialog" role="dialog" aria-modal="true" style={{ maxWidth: 520 }}>
            <header className="external-ai-help-header">
              <h2 className="external-ai-help-title">统一发行说明</h2>
              <button
                type="button"
                className="external-ai-help-close-btn"
                aria-label="关闭"
                onClick={() => setCapabilitiesModalOpen(false)}
              >
                <svg viewBox="0 0 24 24" width="18" height="18" stroke="currentColor" strokeWidth="2" fill="none">
                  <line x1="18" y1="6" x2="6" y2="18" />
                  <line x1="6" y1="6" x2="18" y2="18" />
                </svg>
              </button>
            </header>
            <div className="external-ai-help-body">
              <div className="external-ai-help-notice">
                <strong>发行范围：</strong>
                核心和官方组件随同一套发行版本安装、升级；组件状态以实际安装和运行检查为准。
              </div>
              <div style={{ fontSize: 13, color: "var(--text-muted)", lineHeight: 1.6, marginTop: 12 }}>
                <p style={{ marginBottom: 8 }}>
                  • 镜像部署：创建计划、明确确认、查询真实操作结果
                </p>
                <p style={{ marginBottom: 8 }}>
                  • 源码构建：此页面尚未提供入口
                </p>
                <p style={{ marginBottom: 8 }}>
                  • 应用网关：此页面尚未提供域名入口
                </p>
                <p style={{ color: "var(--text-faint)", marginTop: 12 }}>
                  当前镜像应用只发布到服务器本机，公网域名与 HTTPS 需另行验收。
                </p>
              </div>
            </div>
            <footer className="external-ai-help-footer">
              <button type="button" className="btn-white" onClick={() => setCapabilitiesModalOpen(false)}>
                知道了
              </button>
            </footer>
          </div>
        </div>
      )}

      {/* 外部 AI 帮助对话框（仅展示真实 CLI 指令） */}
      <CoreHelp
        open={helpOpen}
        onClose={() => setHelpOpen(false)}
        onToast={showToast}
      />

      {/* 全局 Toast */}
      <Toast toast={toast} />
    </div>
  );
}

function executorSummary(status: CoreStatus): string {
  const parts = [
    status.executor.container ? "容器运行已连接" : "容器运行未连接",
    status.executor.source_build ? "源码构建已连接" : "源码构建未连接",
    status.executor.gateway ? "域名与 HTTPS 已连接" : "域名与 HTTPS 未连接",
  ];
  return parts.join("，");
}
