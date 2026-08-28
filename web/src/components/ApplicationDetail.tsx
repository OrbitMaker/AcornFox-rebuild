import type { ApplicationDetail as ApplicationDetailFact, ApplicationSummary } from '../api/types';
import { RequestState } from './RequestState';
import './ApplicationDetail.css';

export interface ApplicationDetailProps {
  application?: ApplicationSummary;
  detail?: ApplicationDetailFact;
  loading: boolean;
  error?: unknown;
  onRefresh: () => void;
}

export function ApplicationDetail({ application, detail, loading, error, onRefresh }: ApplicationDetailProps) {
  if (!application) {
    return <section className="application-detail application-detail--empty" aria-labelledby="application-detail-heading"><h2 id="application-detail-heading">应用详情</h2><p>请先从应用列表选择一个应用。</p></section>;
  }
  return (
    <section className="application-detail" aria-labelledby="application-detail-heading">
      <header className="application-detail__header">
        <div><p className="eyebrow">已选择应用</p><h2 id="application-detail-heading">{application.name}</h2><p><code>{application.id}</code></p></div>
        <button type="button" onClick={onRefresh} disabled={loading}>{loading ? '正在刷新…' : '刷新详情'}</button>
      </header>
      <RequestState error={error} loading={loading && !detail} onRetry={onRefresh} />
      {detail && (
        <>
          <dl className="application-detail__facts">
            <div><dt>创建时间</dt><dd>{detail.createdAt}</dd></div>
            <div><dt>更新时间</dt><dd>{detail.updatedAt}</dd></div>
            <div><dt>Source upload</dt><dd>{detail.sourceUploadId ?? '尚未绑定'}</dd></div>
            <div><dt>运行状态</dt><dd>{detail.access.runtimeReady ? '运行就绪' : '未就绪'}</dd></div>
            <div><dt>IP fallback</dt><dd>{detail.access.ipFallback ?? '不可用'}</dd></div>
            <div><dt>平台地址</dt><dd>{detail.access.platformAddress?.hostname ?? '未生成'}</dd></div>
            <div><dt>路由</dt><dd>{detail.access.route.serving ? '正在服务' : detail.access.route.desired ? '已记录目标' : '未配置'}</dd></div>
            <div><dt>证书</dt><dd>{detail.access.certificate.status}</dd></div>
          </dl>
          <div className="application-detail__domains">
            <h3>应用域名</h3>
            {detail.access.customDomains.length === 0 ? <p>暂无客户域名。</p> : <ul>{detail.access.customDomains.map((domain) => <li key={domain.id}><span>{domain.hostname}</span><small>{domain.status}{domain.serving ? ' · 正在服务' : ''}</small></li>)}</ul>}
          </div>
        </>
      )}
    </section>
  );
}
