import { type FormEvent, useState } from "react";
import { Navigate, useNavigate } from "react-router-dom";

import { useAuth } from "../features/auth/AuthProvider";
import { ApiClientError } from "../lib/api/client";

export function SetupPage() {
  const auth = useAuth();
  const navigate = useNavigate();
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  if (auth.loading || auth.initialized === null) {
    return <main className="center-screen">正在检查初始化状态…</main>;
  }

  if (auth.initialized) {
    return <Navigate to={auth.authenticated ? "/" : "/login"} replace />;
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);

    if (password !== confirmation) {
      setError("两次输入的密码不一致。");
      return;
    }

    setSubmitting(true);
    try {
      await auth.setupAdmin({ username, password });
      navigate("/login", { replace: true });
    } catch (cause) {
      if (cause instanceof ApiClientError) {
        const fieldMessage =
          cause.fieldErrors &&
          Object.values(cause.fieldErrors).flat().find(Boolean);
        setError(fieldMessage ?? cause.message);
      } else {
        setError("初始化失败，请确认当前页面从 naos 本机访问。");
      }
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <main className="auth-layout">
      <section className="auth-hero">
        <div className="brand-mark" aria-hidden="true">n</div>
        <p className="eyebrow">First run</p>
        <h1>建立第一个管理员账户。</h1>
        <p>
          首次初始化只允许从本机调用，完成后这个入口会永久关闭。
        </p>
      </section>

      <section className="auth-card">
        <p className="eyebrow">Bootstrap</p>
        <h2>初始化管理员</h2>
        <form className="form-stack" onSubmit={submit}>
          <label>
            <span>管理员用户名</span>
            <input
              autoComplete="username"
              required
              value={username}
              onChange={(event) => setUsername(event.target.value)}
            />
          </label>
          <label>
            <span>密码</span>
            <input
              autoComplete="new-password"
              minLength={12}
              required
              type="password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
            />
          </label>
          <label>
            <span>确认密码</span>
            <input
              autoComplete="new-password"
              minLength={12}
              required
              type="password"
              value={confirmation}
              onChange={(event) => setConfirmation(event.target.value)}
            />
          </label>

          {error ? <div className="inline-error">{error}</div> : null}

          <button className="button primary" disabled={submitting} type="submit">
            {submitting ? "正在初始化…" : "创建管理员"}
          </button>
        </form>
      </section>
    </main>
  );
}
