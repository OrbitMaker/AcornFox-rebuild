import { IconPlus, IconRefresh } from '@douyinfe/semi-icons';
import { Button, Empty, Table, Tag } from '@douyinfe/semi-ui';
import type { ApplicationSummary } from '../api/types';
import { PublishingStatusTag } from './PublishingStatus';
import { DomainAccessStatus } from '../features/domains/DomainAccessStatus';
import { RequestState } from './RequestState';
import './ApplicationList.css';

export interface ApplicationListProps {
  applications: ApplicationSummary[];
  loading: boolean;
  error?: unknown;
  selectedApplicationId?: string;
  onCreate: () => void;
  onRefresh: () => void;
  onSelect: (applicationId: string) => void;
}

const sourceLabels = {
  git: 'Git 来源',
  folder: '文件夹上传',
  archive: '归档上传',
} as const;

function formatUpdatedAt(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.valueOf())) return '时间未知';
  return new Intl.DateTimeFormat('zh-CN', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }).format(date);
}

export function ApplicationList({ applications, loading, error, selectedApplicationId, onCreate, onRefresh, onSelect }: ApplicationListProps) {
  const columns = [
    {
      title: '应用',
      dataIndex: 'name',
      key: 'name',
      render: (_name: string, application: ApplicationSummary) => (
        <button className={`application-select ${selectedApplicationId === application.id ? 'is-selected' : ''}`} type="button" aria-pressed={selectedApplicationId === application.id} onClick={() => onSelect(application.id)}>
          <span className="application-avatar" aria-hidden="true">{application.name.slice(0, 1).toUpperCase()}</span>
          <span>
            <strong>{application.name}</strong>
            <small>{application.slug}</small>
          </span>
        </button>
      ),
    },
    {
      title: '来源',
      dataIndex: 'source',
      key: 'source',
      render: (source: ApplicationSummary['source']) => (
        <div className="source-cell">
          <span>{sourceLabels[source.kind]}</span>
          <small title={source.locator}>{source.locator ?? '待接入来源'}</small>
        </div>
      ),
    },
    {
      title: '发布',
      dataIndex: 'publishing',
      key: 'publishing',
      render: (snapshot: ApplicationSummary['publishing']) => <PublishingStatusTag snapshot={snapshot} compact />,
    },
    {
      title: '运行',
      dataIndex: 'runtimeStatus',
      key: 'runtimeStatus',
      render: (runtimeStatus: ApplicationSummary['runtimeStatus'], application: ApplicationSummary) => (
        <div className="runtime-cell">
          <Tag color={runtimeStatus === 'running' ? 'green' : runtimeStatus === 'attention' ? 'amber' : 'grey'} size="small">
            {runtimeStatus === 'running' ? '运行正常' : runtimeStatus === 'attention' ? '需关注' : runtimeStatus === 'partial' ? '部分异常' : runtimeStatus === 'stopped' ? '已停止' : '待确认'}
          </Tag>
          {application.access
            ? <DomainAccessStatus snapshot={application.access} compact />
            : <small>{application.serving ? '对外入口可用' : application.runtimeReady ? '内部运行就绪' : '尚未就绪'}</small>}
        </div>
      ),
    },
    {
      title: '最近更新',
      dataIndex: 'updatedAt',
      key: 'updatedAt',
      render: (updatedAt: string) => <span className="muted-cell">{formatUpdatedAt(updatedAt)}</span>,
    },
  ];

  return (
    <section className="page-section" aria-labelledby="applications-heading">
      <header className="section-heading">
        <div>
          <p className="eyebrow">应用</p>
          <h1 id="applications-heading">我的应用</h1>
          <p className="section-subtitle">在客户自有单机上管理源码、发布和运行入口。</p>
        </div>
        <div className="heading-actions">
          <Button icon={<IconRefresh />} theme="borderless" onClick={onRefresh} loading={loading}>刷新</Button>
          <Button icon={<IconPlus />} theme="solid" type="primary" onClick={onCreate}>创建应用</Button>
        </div>
      </header>
      <RequestState error={error} title="应用列表加载失败" onRetry={onRefresh} />
      {applications.length === 0 && !loading ? (
        <div className="empty-card">
          <Empty description="还没有应用" />
          <Button theme="solid" type="primary" onClick={onCreate}>接入第一个应用</Button>
        </div>
      ) : (
        <div className="table-card">
          <Table
            rowKey="id"
            columns={columns}
            dataSource={applications}
            loading={loading}
            pagination={false}
            size="middle"
          />
        </div>
      )}
    </section>
  );
}
