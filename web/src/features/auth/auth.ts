export const SESSION_COOKIE_NAME = '__Host-open_card_session';
export const CSRF_COOKIE_NAME = '__Host-open_card_csrf';
export const CSRF_HEADER_NAME = 'X-Open-Card-CSRF';

export type AuthMode = 'live' | 'stub';

export type AuthSession =
  | { authenticated: false; mode: AuthMode }
  | { authenticated: true; mode: AuthMode; username?: string; expiresAt?: string };

export interface AuthLoginInput {
  username: string;
  password: string;
}

export interface PasswordChangeInput {
  currentPassword: string;
  newPassword: string;
}

export interface AuthClient {
  readonly authMode: AuthMode;
  getSession(signal?: AbortSignal): Promise<AuthSession>;
  login(input: AuthLoginInput, signal?: AbortSignal): Promise<AuthSession>;
  logout(signal?: AbortSignal): Promise<void>;
  changePassword(input: PasswordChangeInput, signal?: AbortSignal): Promise<AuthSession>;
}

export function authErrorMessage(error: unknown, fallback = '认证请求未完成，请稍后重试。'): string {
  const status = typeof error === 'object' && error !== null && 'status' in error
    ? (error as { status?: unknown }).status
    : undefined;
  if (status === 401) return '管理员会话已失效，请重新登录。';
  if (status === 429) return '尝试次数过多，请稍后再试。';
  if (status === 503) return '控制面暂时不可用，请稍后重试。';
  return fallback;
}

export function isAuthenticatedSession(session: AuthSession): session is AuthSession & { authenticated: true } {
  return session.authenticated;
}
