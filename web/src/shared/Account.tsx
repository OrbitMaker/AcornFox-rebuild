import { useState } from "react";
import type { FormEvent } from "react";
import { AcornFoxRequestError } from "./auth-transport";

export interface AccountProps {
  api: { changePassword(currentPassword: string, newPassword: string): Promise<void> };
  onLogout: () => void;
  onBack?: () => void;
}

export function Account({ api, onLogout, onBack }: AccountProps) {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string>();

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (next !== confirm) {
      setMessage("两次输入的新密码不一致。");
      return;
    }
    setBusy(true);
    setMessage(undefined);
    try {
      await api.changePassword(current, next);
      onLogout();
    } catch (error) {
      const msg = error instanceof AcornFoxRequestError ? error.message : "请求未完成，请手动重试。";
      setMessage(msg);
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="af-form-page" style={{ maxWidth: 440, margin: "40px auto", padding: "0 20px" }}>
      <header style={{ marginBottom: 20 }}>
        {onBack && (
          <button
            type="button"
            className="btn-ghost"
            style={{ marginBottom: 12, padding: "4px 10px", fontSize: 13 }}
            onClick={onBack}
          >
            ← 返回桌面
          </button>
        )}
        <h2 style={{ fontSize: 20, fontWeight: 600, color: "var(--text-main)" }}>账户设置</h2>
        <p style={{ fontSize: 13, color: "var(--text-muted)", marginTop: 4 }}>修改管理员登录密码</p>
      </header>
      <form className="af-form" onSubmit={submit} style={{ display: "flex", flexDirection: "column", gap: 16 }}>
        <div className="webos-form-field">
          <label>
            当前密码
            <input
              autoComplete="current-password"
              type="password"
              className="webos-input"
              value={current}
              onChange={(event) => setCurrent(event.target.value)}
            />
          </label>
        </div>
        <div className="webos-form-field">
          <label>
            新密码
            <input
              autoComplete="new-password"
              type="password"
              className="webos-input"
              value={next}
              onChange={(event) => setNext(event.target.value)}
            />
          </label>
        </div>
        <div className="webos-form-field">
          <label>
            确认新密码
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
          style={{ width: "100%", height: 42, marginTop: 8 }}
          disabled={busy || !current || !next || !confirm}
        >
          {busy ? "正在提交…" : "修改密码并重新登录"}
        </button>
      </form>
    </section>
  );
}
