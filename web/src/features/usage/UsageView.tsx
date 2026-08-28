import {
  ANOMALY_SEVERITY_LABELS,
  formatUsageValue,
  type ApplicationUsageFact,
  type UsageAnomaly,
  type UsageMetric,
  type UsageMeasurement,
  type UsageResourceMeasurements,
  type UsageServiceFact,
  type UsageTrendPoint,
  usageFactIdentity,
  usagePercent,
  USAGE_METRIC_LABELS,
} from './usageFacts';

export interface UsageViewProps {
  facts: ApplicationUsageFact;
  mode: 'normal' | 'operations';
}

export function UsageView({ facts, mode }: UsageViewProps) {
  return (
    <section className="usage-view" aria-label={`${facts.applicationName} 用量`}>
      <header className="usage-view__header">
        <div>
          <p className="eyebrow">用量与资源</p>
          <h1>{facts.applicationName}</h1>
          <small>事实版本 {usageFactIdentity(facts)}</small>
        </div>
        <span className="usage-view__mode">{mode === 'normal' ? '普通视图' : '运维视图'}</span>
      </header>
      {mode === 'normal' ? <NormalUsageView facts={facts} /> : <OperationsUsageView facts={facts} />}
      <DisabledAIUsageNotice />
    </section>
  );
}

export interface UsageModeViewProps { facts: ApplicationUsageFact }

export function NormalUsageView({ facts }: UsageModeViewProps) {
  const serviceCount = facts.services.length;
  const warningCount = facts.anomalies.filter((anomaly) => anomaly.severity !== 'info').length;
  return (
    <div className="usage-view__normal">
      <dl className="usage-view__summary">
        <div><dt>运行中的服务</dt><dd>{serviceCount}</dd></div>
        <div><dt>最近观察</dt><dd>{facts.observedAt}</dd></div>
        <div><dt>需要关注</dt><dd>{warningCount === 0 ? '暂无' : `${warningCount} 项`}</dd></div>
      </dl>
      <section aria-labelledby="usage-normal-services">
        <h2 id="usage-normal-services">服务用量</h2>
        <div className="usage-service-cards">
          {facts.services.map((service) => <NormalServiceCard key={service.id} service={service} />)}
        </div>
      </section>
      <AnomalyList anomalies={facts.anomalies} />
    </div>
  );
}

function NormalServiceCard({ service }: { service: UsageServiceFact }) {
  return (
    <article className="usage-service-card">
      <h3>{service.name}</h3>
      <p>{service.runtime} · 发布 {service.releaseId}</p>
      <UsageMeasurements measurements={service.actual} compact />
    </article>
  );
}

export function OperationsUsageView({ facts }: UsageModeViewProps) {
  return (
    <div className="usage-view__operations">
      <p className="usage-view__observed">控制面观测时间：{facts.observedAt}</p>
      <section aria-labelledby="usage-operations-table">
        <h2 id="usage-operations-table">资源实际值与配置上限</h2>
        <table>
          <caption>按服务、发布和运行时长查看资源</caption>
          <thead><tr><th>服务</th><th>发布</th><th>运行时长</th><th>平均值</th><th>峰值</th><th>配置上限</th><th>趋势</th></tr></thead>
          <tbody>{facts.services.map((service) => <OperationsServiceRow key={service.id} service={service} />)}</tbody>
        </table>
      </section>
      <AnomalyList anomalies={facts.anomalies} services={facts.services} />
    </div>
  );
}

function OperationsServiceRow({ service }: { service: UsageServiceFact }) {
  return (
    <tr>
      <th scope="row">{service.name}</th>
      <td>{service.releaseId}</td>
      <td>{service.runtime}<br /><small>启动于 {service.startedAt}</small></td>
      <td><UsageMeasurements measurements={service.average} /></td>
      <td><UsageMeasurements measurements={service.peak} /></td>
      <td><UsageMeasurements measurements={service.configured} /></td>
      <td><TrendSummary trend={service.trend} /></td>
    </tr>
  );
}

function UsageMeasurements({ measurements, compact = false }: { measurements: UsageResourceMeasurements; compact?: boolean }) {
  return <ul className={`usage-measurements ${compact ? 'usage-measurements--compact' : ''}`}>{(Object.keys(USAGE_METRIC_LABELS) as UsageMetric[]).map((metric) => {
    const measurement: UsageMeasurement = measurements[metric];
    const percent = usagePercent(measurement);
    return <li key={metric}><span>{USAGE_METRIC_LABELS[metric]}</span><strong>{formatUsageValue(measurement)}</strong>{!compact && <small>{percent === null ? '上限未配置' : `${percent}%`}</small>}</li>;
  })}</ul>;
}

function TrendSummary({ trend }: { trend: readonly UsageTrendPoint[] }) {
  const latest = trend.at(-1);
  if (!latest) return <span>暂无趋势数据</span>;
  return (
    <ul className="usage-trend-summary">
      {(Object.keys(USAGE_METRIC_LABELS) as UsageMetric[]).map((metric) => (
        <li key={metric}>{USAGE_METRIC_LABELS[metric]} {formatUsageValue(latest[metric])}</li>
      ))}
    </ul>
  );
}

function AnomalyList({ anomalies, services = [] }: { anomalies: readonly UsageAnomaly[]; services?: readonly UsageServiceFact[] }) {
  return (
    <section className="usage-anomalies" aria-labelledby="usage-anomalies-heading">
      <h2 id="usage-anomalies-heading">异常关联</h2>
      {anomalies.length === 0 ? <p>暂无异常记录。</p> : (
        <ul>{anomalies.map((anomaly) => {
          const service = services.find((item) => item.id === anomaly.relatedServiceId);
          return <li key={anomaly.id}><strong>{ANOMALY_SEVERITY_LABELS[anomaly.severity]}</strong> {anomaly.summary} <small>{anomaly.observedAt}{service ? ` · 关联服务 ${service.name}` : ''}{anomaly.relatedReleaseId ? ` · 发布 ${anomaly.relatedReleaseId}` : ''}</small></li>;
        })}</ul>
      )}
    </section>
  );
}

function DisabledAIUsageNotice() {
  return <aside className="usage-ai-disabled" role="note"><strong>AI 分析已关闭</strong><span>用量展示、趋势与异常关联不依赖 AI。</span></aside>;
}
