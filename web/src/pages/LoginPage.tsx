import { type FormEvent, useState } from "react";
import { Navigate } from "react-router-dom";

import { useAuth } from "../features/auth/AuthProvider";
import { ApiClientError } from "../lib/api/client";

export function LoginPage() {
  const auth = useAuth();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  if (auth.loading || auth.initialized === null) {
    return <main className="center-screen">正在读取登录状态…</main>;
  }

  if (!auth.initialized) {
    return <Navigate to="/setup" replace />;
  }

  if (auth.authenticated) {
    return <Navigate to="/" replace />;
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    setSubmitting(true);

    try {
      await auth.login({ username, password });
    } catch (cause) {
      setError(
        cause instanceof ApiClientError
          ? cause.message
          : "无法连接 naos，请检查服务状态。",
      );
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <main className="auth-layout">
      <section className="auth-hero">
        <div className="brand-mark" aria-hidden="true">n</div>
        <p className="eyebrow">naos control plane</p>
        <h1>文件服务统一管理，协议数据面各司其职。</h1>
        <p>
          管理 SMB、WebDAV 与 NFS，共享同一套用户、ACL、安全审计与诊断语义。
        </p>
      </section>

      <section className="auth-card">
        <p className="eyebrow">Sign in</p>
        <h2>登录 naos</h2>
        <p className="muted">
          会话保存在 HttpOnly Cookie 中；浏览器不会持久化管理 token。
        </p>

        <form className="form-stack" onSubmit={submit}>
          <label>
            <span>用户名</span>
            <input
              autoComplete="username"
              autoFocus
              required
              value={username}
              onChange={(event) => setUsername(event.target.value)}
            />
          </label>
          <label>
            <span>密码</span>
            <input
              autoComplete="current-password"
              required
              type="password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
            />
          </label>

          {error ? <div className="inline-error">{error}</div> : null}

          <button className="button primary" disabled={submitting} type="submit">
            {submitting ? "正在登录…" : "登录"}
          </button>
        </form>
      </section>
    </main>
  );
}
