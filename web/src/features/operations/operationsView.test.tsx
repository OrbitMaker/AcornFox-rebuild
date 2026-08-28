import { renderToStaticMarkup } from 'react-dom/server';
import { ApplicationOperationsView } from './ApplicationOperationsView';
import {
  canRequestOperation,
  formatBytes,
  operationFactIdentity,
  operationRequestFor,
  type ApplicationOperationsFact,
} from './operationsView';

const facts: ApplicationOperationsFact = {
  version: 'ops-v17',
  observedAt: '2026-08-25T01:00:00.000Z',
  applicationId: 'app_notes',
  applicationName: '团队知识库',
  serving: true,
  impact: 'API 服务降级，网页入口仍可访问。',
  nextStep: '优先重启异常 API 服务。',
  services: [
    {
      id: 'frontend', name: 'frontend', health: 'healthy', required: true,
      resources: { cpuMillicores: 42, memoryBytes: 128 << 20, diskBytes: 1 << 30, networkRxBytes: 2048, networkTxBytes: 4096, restartCount: 0 },
    },
    {
      id: 'api', name: 'api', health: 'unhealthy', required: true, exitReason: 'health check failed',
      resources: { cpuMillicores: 880, memoryBytes: 512 << 20, diskBytes: 2 << 30, networkRxBytes: 1024, networkTxBytes: 512, restartCount: 3 },
    },
  ],
  actions: [
    { action: 'restart', status: 'idle', targetServiceId: 'api', enabled: true },
    { action: 'redeploy', status: 'running', operationId: 'op_redeploy', enabled: true, message: '正在等待健康检查。' },
    { action: 'rollback', status: 'blocked', enabled: false, message: '尚未确认上一成功版本。' },
  ],
  dataRollbackSupported: false,
};

describe('M4 application operations views', () => {
  it('shares the same versioned observation facts between normal and operations views', () => {
    const normal = renderToStaticMarkup(<ApplicationOperationsView facts={facts} mode="normal" />);
    const detailed = renderToStaticMarkup(<ApplicationOperationsView facts={facts} mode="operations" />);

    expect(normal).toContain('事实版本 ops-v17@2026-08-25T01:00:00.000Z');
    expect(detailed).toContain('事实版本 ops-v17@2026-08-25T01:00:00.000Z');
    expect(normal).toContain('API 服务降级，网页入口仍可访问。');
    expect(detailed).toContain('服务实际状态与资源观测');
    expect(detailed).toContain('512 MiB');
  });

  it('renders source action state and does not invent completion', () => {
    const markup = renderToStaticMarkup(<ApplicationOperationsView facts={facts} mode="normal" />);

    expect(markup).toContain('正在等待健康检查。');
    expect(markup).toContain('执行中');
    expect(markup).toContain('disabled');
    expect(markup).toContain('不会回滚数据库或数据卷。');
  });

  it('uses an expected fact version for action requests and permits idle actions only', () => {
    const restart = facts.actions[0];
    const redeploy = facts.actions[1];

    expect(operationFactIdentity(facts)).toBe('ops-v17@2026-08-25T01:00:00.000Z');
    expect(operationRequestFor(facts, restart)).toEqual({ action: 'restart', targetServiceId: 'api', expectedVersion: 'ops-v17' });
    expect(canRequestOperation(restart)).toBe(true);
    expect(canRequestOperation(redeploy)).toBe(false);
    expect(formatBytes(512 << 20)).toBe('512 MiB');
  });
});
