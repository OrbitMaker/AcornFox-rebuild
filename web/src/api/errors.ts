export type ApiErrorKind =
  | 'auth'
  | 'conflict'
  | 'size'
  | 'media'
  | 'validation'
  | 'rate'
  | 'unavailable'
  | 'timeout'
  | 'network'
  | 'http';

export class ApiRequestError extends Error {
  constructor(
    public readonly status: number | undefined,
    message: string,
    public readonly kind: ApiErrorKind = 'http',
    public readonly code = status === undefined ? 'api_error' : `http_${status}`,
  ) {
    super(message);
    this.name = 'ApiRequestError';
  }
}

export function classifyStatus(status: number): ApiErrorKind {
  if (status === 401) return 'auth';
  if (status === 409) return 'conflict';
  if (status === 413) return 'size';
  if (status === 415) return 'media';
  if (status === 400 || status === 422) return 'validation';
  if (status === 429) return 'rate';
  if (status === 503 || status >= 500) return 'unavailable';
  return 'http';
}

export function createResponseError(
  status: number,
  fallbackMessage: string,
  body?: unknown,
): ApiRequestError {
  const payload = isSafeErrorBody(body) ? body : undefined;
  const kind = classifyStatus(status);
  const safeFallback: Partial<Record<ApiErrorKind, string>> = {
    auth: '管理员会话已失效，请重新登录。',
    rate: '请求过于频繁，请稍后再试。',
    unavailable: '控制面暂时不可用，请稍后重试。',
  };
  return new ApiRequestError(status, payload?.message ?? safeFallback[kind] ?? fallbackMessage, kind, payload?.code ?? `http_${status}`);
}

export function createTimeoutError(): ApiRequestError {
  return new ApiRequestError(undefined, '请求超时，请稍后重试。', 'timeout', 'request_timeout');
}

export function createNetworkError(): ApiRequestError {
  return new ApiRequestError(undefined, '网络请求未完成，请检查连接后重试。', 'network', 'network_error');
}

function isSafeErrorBody(value: unknown): value is { code: string; message: string } {
  if (typeof value !== 'object' || value === null) return false;
  const candidate = value as { code?: unknown; message?: unknown };
  return typeof candidate.code === 'string' && typeof candidate.message === 'string';
}
