import { useState } from 'react';
import type { FormEvent } from 'react';
import type { AuthClient } from './auth';
import { authErrorMessage } from './auth';

export function PasswordRotation({ client, onCompleted }: { client: AuthClient; onCompleted: () => void }) {
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmation, setConfirmation] = useState('');
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string>();

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(undefined);
    if (!currentPassword || !newPassword) {
      setError('请输入当前密码和新密码。');
      return;
    }
    if (newPassword !== confirmation) {
      setError('两次输入的新密码不一致。');
      return;
    }
    setPending(true);
    try {
      await client.changePassword({ currentPassword, newPassword });
      setCurrentPassword('');
      setNewPassword('');
      setConfirmation('');
      onCompleted();
    } catch (reason) {
      setError(authErrorMessage(reason, '密码轮换未完成，请检查输入后重试。'));
    } finally {
      setPending(false);
    }
  }

  return (
    <section className="password-rotation" aria-labelledby="password-rotation-heading">
      <header><div><p className="eyebrow">访问安全</p><h2 id="password-rotation-heading">轮换管理员密码</h2><p>成功后当前会话立即失效，需要使用新密码重新登录。</p></div></header>
      {error && <div className="auth-message auth-message--error" role="alert">{error}</div>}
      <form className="password-rotation__form" onSubmit={submit} noValidate>
        <label className="auth-field" htmlFor="current-admin-password"><span>当前密码</span><input id="current-admin-password" name="current-password" type="password" autoComplete="current-password" value={currentPassword} onChange={(event) => setCurrentPassword(event.target.value)} disabled={pending} /></label>
        <label className="auth-field" htmlFor="new-admin-password"><span>新密码</span><input id="new-admin-password" name="new-password" type="password" autoComplete="new-password" value={newPassword} onChange={(event) => setNewPassword(event.target.value)} disabled={pending} /></label>
        <label className="auth-field" htmlFor="confirm-admin-password"><span>确认新密码</span><input id="confirm-admin-password" name="confirm-password" type="password" autoComplete="new-password" value={confirmation} onChange={(event) => setConfirmation(event.target.value)} disabled={pending} /></label>
        <button className="auth-secondary-submit" type="submit" disabled={pending}>{pending ? '正在轮换…' : '更新密码并重新登录'}</button>
      </form>
    </section>
  );
}
