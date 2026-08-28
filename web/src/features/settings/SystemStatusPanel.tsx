import type { SystemStatusFact, SystemStatusResult } from '../../api/types';

const statusLabels: Record<SystemStatusFact['node']['readiness'] | SystemStatusFact['platformDomain']['status'] | SystemStatusFact['webhooks']['status'], string> = {
  ready: '就绪',
  not_ready: '未就绪',
  unconfigured: '未配置',
  pending: '处理中',
  failed: '失败',
  configured: '已配置',
};

function capabilityLabel(status: 'not_installed'): string {
  return status === 'not_installed' ? '未安装（后续 Gate 7）' : '未知';
}

function statusLabel(status: keyof typeof statusLabels): string {
  return statusLabels[status];
}

export function SystemStatusPanel({ result, loading }: { result?: SystemStatusResult; loading: boolean }) {
  return (
    <section className="system-status-panel" aria-labelledby="system-status-heading">
      <header>
        <div>
          <p className="eyebrow">实例状态</p>
          <h1 id="system-status-heading">系统状态</h1>
          <p>以下状态全部来自控制面只读事实；未配置或未安装不会被显示为已就绪。</p>
        </div>
        {result?.status === 'available' && <span className="system-status-panel__version">事实 {result.facts.version}</span>}
      </header>
      {loading && <p className="system-status-panel__loading" role="status" aria-live="polite">正在读取系统状态…</p>}
      {!loading && result?.status === 'unavailable' && <div className="system-status-panel__error" role="alert">{result.message}</div>}
      {!loading && result?.status === 'available' && (
        <dl className="system-status-panel__facts">
          <div>
            <dt>当前节点</dt>
            <dd>{result.facts.node.singleNode ? '单节点' : '多节点'} · {statusLabel(result.facts.node.readiness)}</dd>
          </div>
          <div>
            <dt>实例 / 节点 ID</dt>
            <dd>{result.facts.node.instanceId ?? '实例未配置'} / {result.facts.node.nodeId ?? '节点未配置'}</dd>
          </div>
          <div>
            <dt>平台基础域名</dt>
            <dd>{result.facts.platformDomain.baseDomain ?? '未配置'} · {statusLabel(result.facts.platformDomain.status)}</dd>
          </div>
          <div>
            <dt>Webhook</dt>
            <dd>{statusLabel(result.facts.webhooks.status)} · {result.facts.webhooks.enabledCount} 个启用</dd>
          </div>
          <div>
            <dt>备份</dt>
            <dd>{capabilityLabel(result.facts.backup.status)}</dd>
          </div>
          <div>
            <dt>告警</dt>
            <dd>{capabilityLabel(result.facts.alerts.status)}</dd>
          </div>
        </dl>
      )}
    </section>
  );
}
