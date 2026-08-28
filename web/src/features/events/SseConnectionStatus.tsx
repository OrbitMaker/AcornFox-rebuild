import './SseConnectionStatus.css';
import type { PublishConnectionState } from '../../api/types';

export type SseConnectionState = PublishConnectionState;

const definitions: Record<SseConnectionState, { label: string; detail: string }> = {
  connecting: { label: '事件流连接中', detail: '正在建立当前应用的事件流。' },
  connected: { label: '事件流已连接', detail: '当前应用的发布事件会实时更新。' },
  retrying: { label: '事件流重连中', detail: '连接暂时中断，正在按退避策略重试。' },
  offline: { label: '事件流离线', detail: '暂时无法读取实时事件，页面事实不会被伪造。' },
  auth_required: { label: '需要重新登录', detail: '管理员会话已失效，事件流已停止。' },
  closed: { label: '事件流已关闭', detail: '没有选中的应用或订阅已被取消。' },
};

export interface SseConnectionStatusProps {
  state: SseConnectionState;
  lastEventId?: string;
}

export function SseConnectionStatus({ state, lastEventId }: SseConnectionStatusProps) {
  const definition = definitions[state];
  return <aside className={`sse-connection-status sse-connection-status--${state}`} role="status" aria-live="polite"><strong>{definition.label}</strong><span>{definition.detail}</span>{lastEventId && <small>最近事件：{lastEventId}</small>}</aside>;
}
