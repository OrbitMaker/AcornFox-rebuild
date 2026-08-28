import { useState } from 'react';
import type { FormEvent } from 'react';
import type { ApiClient, ApplicationPublishBuildKind, ApplicationPublishResponse } from '../api/types';
import { ApiRequestError } from '../api/errors';
import { RequestState } from './RequestState';

export function PublishApplicationPanel({ applicationId, client, onPublished, onSettled }: { applicationId: string; client: Pick<ApiClient, 'publishApplication'>; onPublished?: (response: ApplicationPublishResponse) => void; onSettled?: () => void }) {
  const [buildKind, setBuildKind] = useState<ApplicationPublishBuildKind>('static');
  const [contextPath, setContextPath] = useState('.');
  const [dockerfilePath, setDockerfilePath] = useState('Dockerfile');
  const [serviceName, setServiceName] = useState('web');
  const [containerPort, setContainerPort] = useState('8080');
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<unknown>();
  const [accepted, setAccepted] = useState<ApplicationPublishResponse>();

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const port = Number(containerPort);
    if (!contextPath.trim() || !serviceName.trim() || !Number.isInteger(port) || port < 1 || port > 65535 || (buildKind === 'dockerfile' && !dockerfilePath.trim())) {
      setError(new ApiRequestError(422, '请填写有效的构建上下文、服务名、端口和 Dockerfile 路径。', 'validation', 'invalid_publish_input'));
      return;
    }
    setPending(true);
    setError(undefined);
    try {
      const response = await client.publishApplication(applicationId, {
        buildKind,
        contextPath: contextPath.trim(),
        dockerfilePath: buildKind === 'dockerfile' ? dockerfilePath.trim() : undefined,
        serviceName: serviceName.trim(),
        containerPort: port,
      });
      setAccepted(response);
      onPublished?.(response);
    } catch (reason) {
      setError(reason);
    } finally {
      setPending(false);
      onSettled?.();
    }
  }

  return (
    <section className="publish-application-panel" aria-labelledby="publish-application-heading">
      <header>
        <div>
          <p className="eyebrow">发布入口</p>
          <h3 id="publish-application-heading">发布应用</h3>
          <p>发布请求最长等待 10 分钟；接受不等于运行就绪，后续状态只来自发布事实和事件流。</p>
        </div>
      </header>
      <RequestState error={error} title="发布未完成" />
      {accepted && <p className="publish-application-panel__accepted" role="status">发布已受理，等待发布事实：{accepted.operationId}</p>}
      <form onSubmit={submit} noValidate>
        <label>构建类型<select value={buildKind} onChange={(event) => setBuildKind(event.target.value as ApplicationPublishBuildKind)} disabled={pending}><option value="static">静态站点</option><option value="dockerfile">Dockerfile</option></select></label>
        <label>构建上下文<input value={contextPath} onChange={(event) => setContextPath(event.target.value)} disabled={pending} /></label>
        {buildKind === 'dockerfile' && <label>Dockerfile 路径<input value={dockerfilePath} onChange={(event) => setDockerfilePath(event.target.value)} disabled={pending} /></label>}
        <label>服务名<input value={serviceName} onChange={(event) => setServiceName(event.target.value)} disabled={pending} /></label>
        <label>容器端口<input type="number" min="1" max="65535" value={containerPort} onChange={(event) => setContainerPort(event.target.value)} disabled={pending} /></label>
        <button type="submit" disabled={pending}>{pending ? '正在提交发布…' : '提交发布'}</button>
      </form>
    </section>
  );
}
