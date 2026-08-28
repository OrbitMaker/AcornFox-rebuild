import { ApiRequestError } from '../api/errors';
import './RequestState.css';

export interface RequestStateProps {
  error?: unknown;
  message?: string;
  title?: string;
  onRetry?: () => void;
  loading?: boolean;
}

export function requestStateMessage(error: unknown, fallback = '请求未完成，请稍后重试。'): string {
  if (error instanceof ApiRequestError) {
    if (error.kind === 'auth') return '管理员会话已失效，请重新登录。';
    if (error.kind === 'conflict') return '状态已发生变化，请刷新后重试。';
    if (error.kind === 'validation') return '提交信息未通过校验，请检查后重试。';
    if (error.kind === 'rate') return '请求过于频繁，请稍后重试。';
    if (error.kind === 'unavailable') return '控制面暂时不可用，请稍后重试。';
    if (error.kind === 'timeout') return '请求超时，请稍后重试。';
    if (error.kind === 'network') return '网络请求未完成，请检查连接后重试。';
    return error.message || fallback;
  }
  if (typeof error === 'string' && error.length > 0) return error;
  if (error instanceof Error && error.message.length > 0) return error.message;
  return fallback;
}

export function RequestState({ error, message, title = '请求未完成', onRetry, loading = false }: RequestStateProps) {
  if (loading) return <p className="request-state request-state--loading" role="status" aria-live="polite">正在读取控制面事实…</p>;
  if (!error && !message) return null;
  return (
    <div className="request-state request-state--error" role="alert">
      <div><strong>{title}</strong><p>{message ?? requestStateMessage(error)}</p></div>
      {onRetry && <button type="button" onClick={onRetry}>重试</button>}
    </div>
  );
}
