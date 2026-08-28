import { useState } from 'react';
import type { FormEvent } from 'react';
import type { AuthClient, AuthSession } from './auth';
import { authErrorMessage } from './auth';

export function LoginView({
  client,
  message,
  onAuthenticated,
}: {
  client: AuthClient;
  message?: string;
  onAuthenticated: (session: AuthSession) => void;
}) {
  const [username, setUsername] = useState('admin');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string>();

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(undefined);
    if (!username.trim() || !password) {
      setError('请输入管理员账号和密码。');
      return;
    }
    setPending(true);
    try {
      const session = await client.login({ username: username.trim(), password });
      setPassword('');
      onAuthenticated(session);
    } catch (reason) {
      setPassword('');
      setError(authErrorMessage(reason, '管理员账号或密码不正确。'));
    } finally {
      setPending(false);
    }
  }

  return (
    <main className="auth-shell">
      <section className="auth-card" aria-labelledby="login-heading">
        <div className="auth-card__brand"><span className="brand-mark">OC</span><span><strong>Open Card</strong><small>自部署应用控制台</small></span></div>
        <p className="eyebrow">管理员入口</p>
        <h1 id="login-heading">登录当前实例</h1>
        <p className="auth-card__intro">使用安装时创建的单管理员账号进入控制面。</p>
        {client.authMode === 'stub' && <aside className="auth-boundary" role="note"><strong>本地演示模式</strong><span>当前认证只在本页面内存中生效，不连接真实控制面；生产 Live 切换属于后续 Gate 3。</span></aside>}
        {message && <div className="auth-message" role="status">{message}</div>}
        {error && <div className="auth-message auth-message--error" role="alert">{error}</div>}
        <form className="auth-form" onSubmit={submit} noValidate>
          <label className="auth-field" htmlFor="auth-username"><span>管理员账号</span><input id="auth-username" name="username" type="text" autoComplete="username" value={username} onChange={(event) => setUsername(event.target.value)} disabled={pending} /></label>
          <label className="auth-field" htmlFor="auth-password"><span>密码</span><span className="auth-password-control"><input id="auth-password" name="password" type={showPassword ? 'text' : 'password'} autoComplete="current-password" value={password} onChange={(event) => setPassword(event.target.value)} disabled={pending} /><button type="button" className="auth-password-toggle" aria-pressed={showPassword} onClick={() => setShowPassword((value) => !value)}>{showPassword ? '隐藏' : '显示'}</button></span></label>
          <button className="auth-submit" type="submit" disabled={pending}>{pending ? '正在验证…' : '登录控制台'}</button>
        </form>
        <p className="auth-card__note">密码可直接粘贴，也支持浏览器密码管理器填充。</p>
      </section>
    </main>
  );
}
