import { useState } from "react";
import type { FormEvent } from "react";
import { ReleaseSourceLink } from "./ReleaseSourceLink";
import { AcornFoxRequestError } from "./auth-transport";

export interface LoginProps {
  api: { login(password: string): Promise<unknown> };
  onReady: () => void;
}

export function Login({ api, onReady }: LoginProps) {
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string>();

  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setMessage(undefined);
    try {
      await api.login(password);
      setPassword("");
      onReady();
    } catch (error) {
      const msg = error instanceof AcornFoxRequestError ? error.message : "请求未完成，请手动重试。";
      setMessage(msg);
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="webos-login-wrap">
      <section className="webos-login-card" aria-labelledby="login-title">
        <div className="webos-login-logo">
          <svg viewBox="0 0 24 24" width="28" height="28" stroke="currentColor" strokeWidth="2" fill="none" strokeLinecap="round" strokeLinejoin="round">
            <path d="M12 2v20M2 12h20M4.93 4.93l14.14 14.14M4.93 19.07l14.14-14.14" />
          </svg>
        </div>
        <a className="af-brand" href="/">AcornFox</a>
        <p className="af-kicker">本机应用管理</p>
        <h1 id="login-title">登录管理台</h1>
        <form onSubmit={submit} style={{ width: "100%" }}>
          <div className="webos-form-field">
            <label>
              管理员密码
              <input
                autoFocus
                autoComplete="current-password"
                type="password"
                className="webos-input"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
              />
            </label>
          </div>
          {message && <p className="af-note af-note--error" role="alert">{message}</p>}
          <button
            className="webos-btn-primary"
            style={{ width: "100%", height: 42 }}
            disabled={busy || !password}
          >
            {busy ? "正在登录…" : "登录"}
          </button>
        </form>
        <p className="af-recovery">核心原型暂未提供离线恢复入口；如遗忘管理员凭据，请联系主机运维人员。</p>
        <ReleaseSourceLink />
      </section>
    </main>
  );
}
