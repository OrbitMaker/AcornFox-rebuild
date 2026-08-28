import {
  OPERATION_ACTION_LABELS,
  OPERATION_ACTION_STATUS_LABELS,
  SERVICE_HEALTH_LABELS,
  canRequestOperation,
  formatBytes,
  operationActionFacts,
  operationFactIdentity,
  operationRequestFor,
  type ApplicationOperationsFact,
  type OperationRequest,
  type OperationsViewMode,
  type ServiceHealth,
} from './operationsView';

export interface ApplicationOperationsViewProps {
  facts: ApplicationOperationsFact;
  mode: OperationsViewMode;
  onModeChange?: (mode: OperationsViewMode) => void;
  onRequestOperation?: (request: OperationRequest) => void;
}

const healthClass: Record<ServiceHealth, string> = {
  healthy: 'is-healthy',
  degraded: 'is-degraded',
  unhealthy: 'is-unhealthy',
  unknown: 'is-unknown',
};

/**
 * The normal and operations views deliberately receive the exact same facts
 * object. A mode switch changes presentation only; it never creates a second
 * source of status or synthesizes a successful action.
 */
export function ApplicationOperationsView({
  facts,
  mode,
  onModeChange,
  onRequestOperation,
}: ApplicationOperationsViewProps) {
  const factIdentity = operationFactIdentity(facts);
  return (
    <section className="application-operations" aria-label={`${facts.applicationName} 运行与运维`}>
      <header className="application-operations__header">
        <div>
          <p className="eyebrow">运行与运维</p>
          <h1>{facts.applicationName}</h1>
          <small>事实版本 {factIdentity}</small>
        </div>
        <div className="application-operations__mode" role="group" aria-label="视图模式">
          <button type="button" aria-pressed={mode === 'normal'} onClick={() => onModeChange?.('normal')}>普通视图</button>
          <button type="button" aria-pressed={mode === 'operations'} onClick={() => onModeChange?.('operations')}>运维视图</button>
        </div>
      </header>
      {mode === 'normal'
        ? <NormalOperationsView facts={facts} onRequestOperation={onRequestOperation} />
        : <DetailedOperationsView facts={facts} onRequestOperation={onRequestOperation} />}
    </section>
  );
}

function NormalOperationsView({
  facts,
  onRequestOperation,
}: Pick<ApplicationOperationsViewProps, 'facts' | 'onRequestOperation'>) {
  const unhealthy = facts.services.filter((service) => service.health === 'unhealthy').length;
  const degraded = facts.services.filter((service) => service.health === 'degraded').length;
  return (
    <div className="application-operations__normal">
      <dl className="application-operations__summary">
        <div><dt>对外服务</dt><dd>{facts.serving ? '服务中' : '未对外服务'}</dd></div>
        <div><dt>服务健康</dt><dd>{unhealthy > 0 ? `${unhealthy} 个异常` : degraded > 0 ? `${degraded} 个降级` : '全部健康'}</dd></div>
        <div><dt>影响</dt><dd>{facts.impact}</dd></div>
        <div><dt>下一步</dt><dd>{facts.nextStep}</dd></div>
      </dl>
      <OperationActions facts={facts} onRequestOperation={onRequestOperation} />
      <DataRollbackNotice />
    </div>
  );
}

function DetailedOperationsView({
  facts,
  onRequestOperation,
}: Pick<ApplicationOperationsViewProps, 'facts' | 'onRequestOperation'>) {
  return (
    <div className="application-operations__detailed">
      <p className="application-operations__observed">控制面观测时间：{facts.observedAt}</p>
      <table>
        <caption>服务实际状态与资源观测</caption>
        <thead>
          <tr><th>服务</th><th>健康</th><th>CPU</th><th>内存</th><th>磁盘</th><th>网络</th><th>重启</th><th>退出原因</th></tr>
        </thead>
        <tbody>
          {facts.services.map((service) => (
            <tr key={service.id}>
              <th scope="row">{service.name}{service.required ? '' : '（可选）'}</th>
              <td><span className={`service-health ${healthClass[service.health]}`}>{SERVICE_HEALTH_LABELS[service.health]}</span></td>
              <td>{service.resources.cpuMillicores} mCPU</td>
              <td>{formatBytes(service.resources.memoryBytes)}</td>
              <td>{formatBytes(service.resources.diskBytes)}</td>
              <td>↓ {formatBytes(service.resources.networkRxBytes)} / ↑ {formatBytes(service.resources.networkTxBytes)}</td>
              <td>{service.resources.restartCount}</td>
              <td>{service.exitReason ?? '无'}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <OperationActions facts={facts} onRequestOperation={onRequestOperation} />
      <DataRollbackNotice />
    </div>
  );
}

function OperationActions({
  facts,
  onRequestOperation,
}: Pick<ApplicationOperationsViewProps, 'facts' | 'onRequestOperation'>) {
  return (
    <section className="application-operations__actions" aria-label="安全运维操作">
      <h2>安全操作</h2>
      <ul>
        {operationActionFacts(facts).map((action) => (
          <li key={action.action}>
            <div>
              <strong>{OPERATION_ACTION_LABELS[action.action]}</strong>
              <span>{OPERATION_ACTION_STATUS_LABELS[action.status]}</span>
              {action.message && <small>{action.message}</small>}
            </div>
            <button
              type="button"
              disabled={!canRequestOperation(action)}
              onClick={() => onRequestOperation?.(operationRequestFor(facts, action))}
            >
              {OPERATION_ACTION_LABELS[action.action]}
            </button>
          </li>
        ))}
      </ul>
    </section>
  );
}

function DataRollbackNotice() {
  return <p className="application-operations__rollback-note" role="note">回滚仅恢复上一成功的程序与配置版本；不会回滚数据库或数据卷。</p>;
}
