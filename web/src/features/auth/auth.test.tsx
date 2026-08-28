import { renderToStaticMarkup } from 'react-dom/server';
import { LoginView } from './LoginView';
import { PasswordRotation } from './PasswordRotation';
import { authErrorMessage, type AuthClient } from './auth';

const stubClient: AuthClient = {
  authMode: 'stub',
  async getSession() { return { authenticated: false, mode: 'stub' }; },
  async login() { return { authenticated: true, mode: 'stub', username: 'admin' }; },
  async logout() {},
  async changePassword() { return { authenticated: false, mode: 'stub' }; },
};

describe('authentication surfaces', () => {
  it('labels stub mode and preserves password-manager-friendly login fields', () => {
    const markup = renderToStaticMarkup(<LoginView client={stubClient} onAuthenticated={() => {}} />);
    expect(markup).toContain('本地演示模式');
    expect(markup).toContain('autoComplete="current-password"');
    expect(markup).toContain('密码可直接粘贴');
  });

  it('renders password rotation without exposing a recovery path', () => {
    const markup = renderToStaticMarkup(<PasswordRotation client={stubClient} onCompleted={() => {}} />);
    expect(markup).toContain('更新密码并重新登录');
    expect(markup).toContain('autoComplete="new-password"');
    expect(markup).not.toContain('找回');
    expect(markup).not.toContain('OIDC');
  });

  it('maps server statuses to non-sensitive messages', () => {
    expect(authErrorMessage({ status: 401 })).toContain('重新登录');
    expect(authErrorMessage({ status: 429 })).toContain('尝试次数过多');
    expect(authErrorMessage({ status: 503 })).toContain('暂时不可用');
    expect(authErrorMessage(new Error('password=must-not-be-shown'))).toContain('认证请求未完成');
    expect(authErrorMessage(new Error('password=must-not-be-shown'))).not.toContain('must-not-be-shown');
  });
});
