import { useMemo } from "react";
import type { components } from "../api/acornfox-generated-schema";
import "./host-metrics.css";

export type HostMetricsResponse = components["schemas"]["HostMetricsResponse"];

export interface HostMetricsViewProps {
  snapshot: HostMetricsResponse | null;
  points: readonly HostMetricsResponse[];
  loading: boolean;
  error?: string;
  stale: boolean;
  onRefresh?: () => void;
}

// ---------------------------------------------------------------------------
// Format Helpers
// ---------------------------------------------------------------------------

function isFiniteNumber(v: unknown): v is number {
  return typeof v === "number" && Number.isFinite(v);
}

function formatBytes(bytes: number | null | undefined): string {
  if (!isFiniteNumber(bytes) || bytes < 0) return "暂未获取";
  if (bytes === 0) return "0 B";
  if (bytes < 1024) return `${bytes} B`;
  const units = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  const idx = Math.min(i, units.length - 1);
  const val = bytes / Math.pow(1024, idx);
  return `${val.toFixed(val >= 100 || idx === 0 ? 0 : 1)} ${units[idx]}`;
}

function formatRate(rate: number | null | undefined, isWarmingUp: boolean): string {
  if (!isFiniteNumber(rate) || rate < 0) return isWarmingUp ? "等待增量" : "暂未获取";
  if (rate === 0) return "0 B/s";
  return `${formatBytes(rate)}/s`;
}

function formatPercent(val: number | null | undefined, isWarmingUp: boolean): string {
  if (!isFiniteNumber(val) || val < 0) return isWarmingUp ? "等待增量" : "暂未获取";
  return `${val.toFixed(1)}%`;
}

function formatDateTime(iso?: string): string {
  if (!iso) return "暂无观测时间";
  const d = new Date(iso);
  if (isNaN(d.getTime())) return iso;
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

function formatTimeOnly(d: Date): string {
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

// ---------------------------------------------------------------------------
// Reusable Trend SVG Renderer (Supports 1 or 2 series, real timestamps)
// ---------------------------------------------------------------------------

export interface TrendSeriesDef {
  name: string;
  lineClass?: string;
  dotClass?: string;
  getValue: (p: HostMetricsResponse) => number | null | undefined;
}

interface TrendPoint {
  x: number;
  y: number;
  val: number;
  t: number;
}

interface TrendChartProps {
  points: readonly HostMetricsResponse[];
  series: TrendSeriesDef[];
  min?: number;
  max?: number;
  emptyText?: string;
  staleAfterSeconds?: number;
}

function TrendChart({ points, series, min, max, emptyText, staleAfterSeconds }: TrendChartProps) {
  const width = 280;
  const height = 42;
  const padX = 6;
  const padY = 4;
  const plotW = width - 2 * padX;
  const plotH = height - 2 * padY;

  const { seriesSegments, hasAnyValid } = useMemo(() => {
    if (points.length === 0) {
      return { seriesSegments: [] as TrendPoint[][][], hasAnyValid: false };
    }

    // 1. Parse real timestamps
    const pointTimes: (number | null)[] = points.map((p) => {
      if (!p.observed_at) return null;
      const t = new Date(p.observed_at).getTime();
      return Number.isFinite(t) ? t : null;
    });

    let minT = Infinity;
    let maxT = -Infinity;
    let validTimeCount = 0;
    for (const t of pointTimes) {
      if (t !== null) {
        if (t < minT) minT = t;
        if (t > maxT) maxT = t;
        validTimeCount++;
      }
    }
    const hasTimeSpan = validTimeCount >= 2 && maxT > minT;
    const timeSpan = hasTimeSpan ? maxT - minT : 0;

    // 2. Determine Y bounds: use fixed min/max or actual finite observed values
    let rangeMin = min ?? 0;
    let rangeMax = max ?? 100;
    if (max === undefined) {
      let actualPeak = 0;
      for (const s of series) {
        for (const p of points) {
          if (p.availability !== "unavailable" && p.availability !== "unsupported") {
            const v = s.getValue(p);
            if (isFiniteNumber(v) && v > actualPeak) actualPeak = v;
          }
        }
      }
      rangeMin = min ?? 0;
      rangeMax = actualPeak > 0 ? actualPeak * 1.15 : 1;
    }
    const span = rangeMax - rangeMin || 1;

    // 3. Compute segments per series (break paths on missing value, unavailable, missing time, or gap > freshness bound)
    let foundAny = false;
    const allSeriesSegments: TrendPoint[][][] = series.map((s) => {
      const segs: TrendPoint[][] = [];
      let cur: TrendPoint[] = [];

      for (let i = 0; i < points.length; i++) {
        const p = points[i];
        const t = pointTimes[i];
        const isBroken =
          p.availability === "unavailable" ||
          p.availability === "unsupported" ||
          t === null;

        const val = !isBroken ? s.getValue(p) : null;
        if (isFiniteNumber(val) && val >= 0) {
          foundAny = true;
          const freshnessSec =
            p.stale_after_seconds > 0
              ? p.stale_after_seconds
              : staleAfterSeconds && staleAfterSeconds > 0
                ? staleAfterSeconds
                : 15;
          const maxGapMs = freshnessSec * 1000;

          // Split series if time gap from previous point exceeds freshness bound or jumps back
          if (cur.length > 0) {
            const prevT = cur[cur.length - 1].t;
            if (t! - prevT > maxGapMs || t! < prevT) {
              segs.push(cur);
              cur = [];
            }
          }

          const x = padX + (hasTimeSpan ? ((t! - minT) / timeSpan) * plotW : plotW / 2);
          const clamped = Math.max(rangeMin, Math.min(rangeMax, val));
          const y = padY + plotH - ((clamped - rangeMin) / span) * plotH;
          cur.push({ x, y, val, t: t! });
        } else {
          if (cur.length > 0) {
            segs.push(cur);
            cur = [];
          }
        }
      }
      if (cur.length > 0) segs.push(cur);
      return segs;
    });

    return { seriesSegments: allSeriesSegments, hasAnyValid: foundAny };
  }, [points, series, min, max, staleAfterSeconds, padX, padY, plotW, plotH]);

  if (points.length === 0 || !hasAnyValid) {
    return <div className="host-metrics-trend-empty">{emptyText ?? "暂无趋势数据"}</div>;
  }

  return (
    <div className="host-metrics-trend-wrap">
      <svg
        viewBox={`0 0 ${width} ${height}`}
        className="host-metrics-trend-svg"
        preserveAspectRatio="none"
        aria-hidden="true"
      >
        <line x1={padX} y1={padY + plotH} x2={padX + plotW} y2={padY + plotH} className="host-metrics-trend-grid" />
        <line x1={padX} y1={padY + plotH / 2} x2={padX + plotW} y2={padY + plotH / 2} className="host-metrics-trend-grid" />
        <line x1={padX} y1={padY} x2={padX + plotW} y2={padY} className="host-metrics-trend-grid" />

        {seriesSegments.map((segs, sIdx) => {
          const sDef = series[sIdx];
          const lineCls = sDef.lineClass ?? "host-metrics-trend-line";
          const dotCls = sDef.dotClass ?? "host-metrics-trend-dot";
          const latestDotCls =
            sDef.lineClass?.includes("--alt")
              ? "host-metrics-trend-latest-dot host-metrics-trend-latest-dot--alt"
              : "host-metrics-trend-latest-dot";

          return segs.map((seg, gIdx) => {
            if (seg.length === 1) {
              return (
                <circle
                  key={`s${sIdx}-g${gIdx}`}
                  cx={seg[0].x}
                  cy={seg[0].y}
                  r={2.5}
                  className={dotCls}
                />
              );
            }
            const d = seg.reduce(
              (acc, pt, idx) => (idx === 0 ? `M ${pt.x.toFixed(1)} ${pt.y.toFixed(1)}` : `${acc} L ${pt.x.toFixed(1)} ${pt.y.toFixed(1)}`),
              "",
            );
            const isLastSeg = gIdx === segs.length - 1;
            const lastPt = seg[seg.length - 1];
            return (
              <g key={`s${sIdx}-g${gIdx}`}>
                <path d={d} className={lineCls} />
                {isLastSeg && (
                  <circle
                    cx={lastPt.x}
                    cy={lastPt.y}
                    r={2.5}
                    className={latestDotCls}
                  />
                )}
              </g>
            );
          });
        })}
      </svg>
      {series.length > 1 && (
        <div className="host-metrics-trend-legend">
          {series.map((s, idx) => (
            <span key={idx} style={{ display: "inline-flex", alignItems: "center", gap: 4 }}>
              <span
                style={{
                  width: 6,
                  height: 6,
                  borderRadius: "50%",
                  backgroundColor: idx === 0 ? "var(--accent-green)" : "#38bdf8",
                }}
              />
              {s.name}
            </span>
          ))}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Fixed MetricCard Component
// ---------------------------------------------------------------------------

interface DualReading {
  label: string;
  value: string;
  dotClass: string;
  isUnavailable?: boolean;
}

interface MetricCardProps {
  title: string;
  icon: JSX.Element;
  tag?: string;
  isStale: boolean;
  primaryValue?: string;
  primarySub?: string;
  isUnavailable?: boolean;
  dualReadings?: DualReading[];
  trendPoints: readonly HostMetricsResponse[];
  trendSeries: TrendSeriesDef[];
  trendMin?: number;
  trendMax?: number;
  trendEmptyText?: string;
  staleAfterSeconds?: number;
}

function MetricCard({
  title,
  icon,
  tag,
  isStale,
  primaryValue,
  primarySub,
  isUnavailable,
  dualReadings,
  trendPoints,
  trendSeries,
  trendMin,
  trendMax,
  trendEmptyText,
  staleAfterSeconds,
}: MetricCardProps) {
  return (
    <article className={`host-metrics-card ${isStale ? "is-stale" : ""}`}>
      <div className="host-metrics-card-header">
        <div className="host-metrics-card-title-wrap">
          <div className="host-metrics-card-icon">{icon}</div>
          <h2 className="host-metrics-card-title">{title}</h2>
        </div>
        {tag && <span className="host-metrics-card-tag">{tag}</span>}
      </div>

      {dualReadings ? (
        <div className="host-metrics-dual-rates">
          {dualReadings.map((r, i) => (
            <div key={i} className="host-metrics-rate-col">
              <span className="host-metrics-rate-label">
                <span className={`host-metrics-rate-dot ${r.dotClass}`} />
                {r.label}
              </span>
              <span className={`host-metrics-rate-val ${r.isUnavailable ? "is-unavailable" : ""}`}>
                {r.value}
              </span>
            </div>
          ))}
        </div>
      ) : (
        <div className="host-metrics-val-row">
          <span className={`host-metrics-val-primary ${isUnavailable ? "is-unavailable" : ""}`}>
            {primaryValue}
          </span>
          {primarySub && <span className="host-metrics-val-sub">{primarySub}</span>}
        </div>
      )}

      <TrendChart
        points={trendPoints}
        series={trendSeries}
        min={trendMin}
        max={trendMax}
        emptyText={trendEmptyText}
        staleAfterSeconds={staleAfterSeconds}
      />
    </article>
  );
}

// ---------------------------------------------------------------------------
// Main HostMetricsView
// ---------------------------------------------------------------------------

export function HostMetricsView({
  snapshot,
  points,
  loading,
  error,
  stale,
  onRefresh,
}: HostMetricsViewProps) {
  // Bound rendering to at most 360 points without synthesizing points
  const boundedPoints = useMemo(() => points.slice(-360), [points]);

  // Derived actual timestamps from bounded points
  const { validTimeCount, firstTimeStr, lastTimeStr } = useMemo(() => {
    const times = boundedPoints
      .map((p) => (p.observed_at ? new Date(p.observed_at).getTime() : NaN))
      .filter((t) => Number.isFinite(t));

    if (times.length === 0) {
      return { validTimeCount: 0, firstTimeStr: "", lastTimeStr: "" };
    }
    const minT = Math.min(...times);
    const maxT = Math.max(...times);
    return {
      validTimeCount: times.length,
      firstTimeStr: formatTimeOnly(new Date(minT)),
      lastTimeStr: formatTimeOnly(new Date(maxT)),
    };
  }, [boundedPoints]);

  // Empty / initial states when snapshot is absent
  if (!snapshot) {
    return (
      <main className="host-metrics-view" aria-label="宿主机器指标">
        <section className="host-metrics-empty-page">
          {loading ? (
            <>
              <span className="host-metrics-spinner" style={{ width: 24, height: 24 }} />
              <h2 className="host-metrics-empty-title">正在读取宿主机器指标…</h2>
              <p className="host-metrics-empty-msg">正在从宿主控制面读取硬件采样，请稍候。</p>
            </>
          ) : error ? (
            <>
              <h2 className="host-metrics-empty-title">无法获取宿主机器指标</h2>
              <p className="host-metrics-empty-msg" role="alert">{error}</p>
              {onRefresh && (
                <button type="button" className="host-metrics-refresh-btn" onClick={onRefresh}>
                  重试连接
                </button>
              )}
            </>
          ) : (
            <>
              <h2 className="host-metrics-empty-title">暂无宿主机器指标</h2>
              <p className="host-metrics-empty-msg">尚未接收到有效指标快照。</p>
              {onRefresh && (
                <button type="button" className="host-metrics-refresh-btn" onClick={onRefresh}>
                  获取指标
                </button>
              )}
            </>
          )}
        </section>
      </main>
    );
  }

  // Snapshot is present: evaluate disconnected / last-known status honestly
  const isLastKnown = Boolean(stale || error);
  const { availability, observed_at, stale_after_seconds, cpu, memory, disk, network } = snapshot;
  const isWarmingUp = availability === "warming_up";
  const isUnavailable = availability === "unavailable";
  const isUnsupported = availability === "unsupported";

  // Honest status badge: if error or stale, NEVER show green current-available
  let statusBadge: { label: string; cls: string };
  if (error) {
    statusBadge = { label: "历史缓存（刷新失败）", cls: "host-metrics-badge--warn" };
  } else if (stale) {
    statusBadge = { label: "数据已过期（历史缓存）", cls: "host-metrics-badge--stale" };
  } else if (availability === "available") {
    statusBadge = { label: "采集正常", cls: "host-metrics-badge--ok" };
  } else if (availability === "warming_up") {
    statusBadge = { label: "预热中", cls: "host-metrics-badge--warn" };
  } else if (availability === "unavailable") {
    statusBadge = { label: "暂不可用", cls: "host-metrics-badge--error" };
  } else {
    statusBadge = { label: "平台不支持", cls: "host-metrics-badge--warn" };
  }

  // Field derivations
  const cpuPercent = cpu?.usage_percent;
  const memUsed = memory?.used_bytes;
  const memTotal = memory?.total_bytes;
  const memAvailable = memory?.available_bytes;
  const memPercent =
    isFiniteNumber(memTotal) && isFiniteNumber(memUsed) && memTotal > 0 && memUsed >= 0
      ? (memUsed / memTotal) * 100
      : undefined;

  const diskUsed = disk?.used_bytes;
  const diskTotal = disk?.total_bytes;
  const diskFree = disk?.free_bytes;
  const diskMount = disk?.mountpoint ?? "/";
  const diskPercent =
    isFiniteNumber(diskTotal) && isFiniteNumber(diskUsed) && diskTotal > 0 && diskUsed >= 0
      ? (diskUsed / diskTotal) * 100
      : undefined;

  const rxRate = network?.rx_bytes_per_second;
  const txRate = network?.tx_bytes_per_second;

  return (
    <main className={`host-metrics-view ${isLastKnown ? "is-stale" : ""}`} aria-label="宿主机器指标">
      {/* 头部与操作栏 */}
      <header className="host-metrics-header">
        <div className="host-metrics-title-group">
          <div className="host-metrics-title-row">
            <h1 className="host-metrics-title">宿主机器指标</h1>
            <span className={`host-metrics-badge ${statusBadge.cls}`}>
              <span className="host-metrics-badge-dot" />
              {statusBadge.label}
            </span>
          </div>
          <div className="host-metrics-meta">
            <span>观测时间: {formatDateTime(observed_at)}</span>
            <span>数据有效期: {stale_after_seconds}s</span>
          </div>
        </div>

        {onRefresh && (
          <button
            type="button"
            className="host-metrics-refresh-btn"
            onClick={onRefresh}
            disabled={loading}
            title="拉取最新机器指标"
          >
            {loading && <span className="host-metrics-spinner" />}
            <span>{loading ? "正在刷新…" : "刷新指标"}</span>
          </button>
        )}
      </header>

      {/* 状态提示（严格陈述事实，不作臆测） */}
      {error && (
        <section className="host-metrics-banner host-metrics-banner--error" role="alert">
          刷新失败：{error}。当前显示最后已知历史观测数据。
        </section>
      )}

      {stale && !error && (
        <section className="host-metrics-banner host-metrics-banner--warn" role="status">
          指标已过期：已超过 {stale_after_seconds}s 数据有效期，当前显示为历史缓存数据。
        </section>
      )}

      {isWarmingUp && !isLastKnown && (
        <section className="host-metrics-banner host-metrics-banner--warn" role="status">
          宿主指标预热中：等待计算增量读数。
        </section>
      )}

      {isUnavailable && !isLastKnown && (
        <section className="host-metrics-banner host-metrics-banner--error" role="status">
          宿主指标暂不可用：服务当前未能提供有效采样。
        </section>
      )}

      {isUnsupported && !isLastKnown && (
        <section className="host-metrics-banner host-metrics-banner--warn" role="status">
          平台不支持：当前运行环境不支持宿主机器指标采集。
        </section>
      )}

      {/* 四大核心指标卡片 */}
      <section className="host-metrics-grid" aria-label="核心指标读数与趋势">
        {/* 1. CPU */}
        <MetricCard
          title="宿主 CPU"
          icon={
            <svg viewBox="0 0 24 24">
              <rect x="4" y="4" width="16" height="16" rx="2" />
              <rect x="9" y="9" width="6" height="6" />
              <line x1="9" y1="1" x2="9" y2="4" /><line x1="15" y1="1" x2="15" y2="4" />
              <line x1="9" y1="20" x2="9" y2="23" /><line x1="15" y1="20" x2="15" y2="23" />
            </svg>
          }
          tag={cpu?.logical_cores !== undefined ? `逻辑核心: ${cpu.logical_cores} 核` : "暂未获取"}
          isStale={isLastKnown}
          primaryValue={formatPercent(cpuPercent, isWarmingUp)}
          primarySub="总体使用率"
          isUnavailable={cpuPercent === undefined}
          trendPoints={boundedPoints}
          trendSeries={[
            {
              name: "CPU",
              getValue: (p) =>
                isFiniteNumber(p.cpu?.usage_percent) && p.cpu.usage_percent >= 0
                  ? p.cpu.usage_percent
                  : null,
            },
          ]}
          trendMin={0}
          trendMax={100}
          staleAfterSeconds={stale_after_seconds}
        />

        {/* 2. 内存 */}
        <MetricCard
          title="物理内存"
          icon={
            <svg viewBox="0 0 24 24">
              <path d="M6 19v-3M10 19v-3M14 19v-3M18 19v-3M6 5v3M10 5v3M14 5v3M18 5v3" />
              <rect x="2" y="8" width="20" height="8" rx="2" />
            </svg>
          }
          tag={memAvailable !== undefined ? `可用: ${formatBytes(memAvailable)}` : undefined}
          isStale={isLastKnown}
          primaryValue={formatPercent(memPercent, false)}
          primarySub={
            isFiniteNumber(memUsed) && isFiniteNumber(memTotal)
              ? `${formatBytes(memUsed)} / ${formatBytes(memTotal)}`
              : "暂未获取"
          }
          isUnavailable={memPercent === undefined}
          trendPoints={boundedPoints}
          trendSeries={[
            {
              name: "内存",
              getValue: (p) =>
                p.memory &&
                isFiniteNumber(p.memory.total_bytes) &&
                isFiniteNumber(p.memory.used_bytes) &&
                p.memory.total_bytes > 0 &&
                p.memory.used_bytes >= 0
                  ? (p.memory.used_bytes / p.memory.total_bytes) * 100
                  : null,
            },
          ]}
          trendMin={0}
          trendMax={100}
          staleAfterSeconds={stale_after_seconds}
        />

        {/* 3. 根磁盘 */}
        <MetricCard
          title="根分区磁盘 (/)"
          icon={
            <svg viewBox="0 0 24 24">
              <line x1="22" y1="12" x2="2" y2="12" />
              <path d="M5.45 5.11L2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z" />
              <line x1="6" y1="16" x2="6.01" y2="16" /><line x1="10" y1="16" x2="10.01" y2="16" />
            </svg>
          }
          tag={`挂载点: ${diskMount}（空闲: ${formatBytes(diskFree)}）`}
          isStale={isLastKnown}
          primaryValue={formatPercent(diskPercent, false)}
          primarySub={
            isFiniteNumber(diskUsed) && isFiniteNumber(diskTotal)
              ? `${formatBytes(diskUsed)} / ${formatBytes(diskTotal)}`
              : "暂未获取"
          }
          isUnavailable={diskPercent === undefined}
          trendPoints={boundedPoints}
          trendSeries={[
            {
              name: "磁盘",
              getValue: (p) =>
                p.disk &&
                isFiniteNumber(p.disk.total_bytes) &&
                isFiniteNumber(p.disk.used_bytes) &&
                p.disk.total_bytes > 0 &&
                p.disk.used_bytes >= 0
                  ? (p.disk.used_bytes / p.disk.total_bytes) * 100
                  : null,
            },
          ]}
          trendMin={0}
          trendMax={100}
          staleAfterSeconds={stale_after_seconds}
        />

        {/* 4. 网络 */}
        <MetricCard
          title="网络吞吐"
          icon={
            <svg viewBox="0 0 24 24">
              <polyline points="22 12 18 12 15 21 9 3 6 12 2 12" />
            </svg>
          }
          tag={`网卡: ${network?.interface ?? "暂未获取"}`}
          isStale={isLastKnown}
          dualReadings={[
            {
              label: "接收 (RX)",
              value: formatRate(rxRate, isWarmingUp),
              dotClass: "host-metrics-rate-dot--rx",
              isUnavailable: rxRate === undefined,
            },
            {
              label: "发送 (TX)",
              value: formatRate(txRate, isWarmingUp),
              dotClass: "host-metrics-rate-dot--tx",
              isUnavailable: txRate === undefined,
            },
          ]}
          trendPoints={boundedPoints}
          trendSeries={[
            {
              name: "RX 接收",
              lineClass: "host-metrics-trend-line",
              dotClass: "host-metrics-trend-dot",
              getValue: (p) =>
                isFiniteNumber(p.network?.rx_bytes_per_second) && p.network.rx_bytes_per_second >= 0
                  ? p.network.rx_bytes_per_second
                  : null,
            },
            {
              name: "TX 发送",
              lineClass: "host-metrics-trend-line host-metrics-trend-line--alt",
              dotClass: "host-metrics-trend-dot host-metrics-trend-dot--alt",
              getValue: (p) =>
                isFiniteNumber(p.network?.tx_bytes_per_second) && p.network.tx_bytes_per_second >= 0
                  ? p.network.tx_bytes_per_second
                  : null,
            },
          ]}
          staleAfterSeconds={stale_after_seconds}
        />
      </section>

      {/* 底部时间戳与缓冲状态摘要 */}
      <footer className="host-metrics-footer">
        <div>
          {validTimeCount === 0 && "趋势缓冲：暂无有效时间戳采样点（最多保留 360 点）。"}
          {validTimeCount === 1 && `趋势缓冲：已记录 1 个采样点（${firstTimeStr}），等待后续采样累积。`}
          {validTimeCount >= 2 && `趋势缓冲：已记录 ${validTimeCount} / 360 点（观测范围：${firstTimeStr} 至 ${lastTimeStr}）。`}
        </div>
        <div>
          数据源自原生 Linux 系统状态采集，仅反映当前主机系统与根文件系统（/），非容器隔离边界。
        </div>
      </footer>
    </main>
  );
}

export default HostMetricsView;
