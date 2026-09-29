import { useState } from "react";
import type { FormEvent } from "react";
import { AcornFoxRequestError } from "./auth-transport";

export interface SetupProps {
  api: { setup(input: { setupToken: string; password: string }): Promise<void> };
  onReady: () => void;
}

export function Setup({ api, onReady }: SetupProps) {
  const [token, setToken] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string>();

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (password !== confirm) {
      setMessage("两次输入的管理员密码不一致。");
      return;
    }
    setBusy(true);
    setMessage(undefined);
    try {
      await api.setup({ setupToken: token, password });
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
      <section className="webos-login-card" aria-labelledby="setup-title">
        <a className="af-brand" href="/">AcornFox</a>
        <p className="af-kicker">首次初始化</p>
        <h1 id="setup-title">创建管理员</h1>
        <p style={{ fontSize: 13, color: "var(--text-muted)", marginBottom: 20 }}>
          请输入安装时生成的一次性凭据。
        </p>
        <form onSubmit={submit} style={{ width: "100%" }}>
          <div className="webos-form-field">
            <label>
              安装凭据
              <input
                autoFocus
                type="password"
                autoComplete="off"
                className="webos-input"
                value={token}
                onChange={(event) => setToken(event.target.value)}
              />
            </label>
          </div>
          <div className="webos-form-field">
            <label>
              管理员密码
              <input
                autoComplete="new-password"
                type="password"
                className="webos-input"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
              />
            </label>
          </div>
          <div className="webos-form-field">
            <label>
              确认管理员密码
              <input
                autoComplete="new-password"
                type="password"
                className="webos-input"
                value={confirm}
                onChange={(event) => setConfirm(event.target.value)}
              />
            </label>
          </div>
          {message && <p className="af-note af-note--error" role="alert">{message}</p>}
          <button
            className="webos-btn-primary"
            style={{ width: "100%", height: 42 }}
            disabled={busy || !token || !password || !confirm}
          >
            {busy ? "正在初始化…" : "完成初始化"}
          </button>
        </form>
        <p className="af-recovery">需要恢复访问时，请联系服务器管理员。</p>
      </section>
    </main>
  );
}
