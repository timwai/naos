import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";
import { Navigate, useNavigate } from "react-router-dom";

import { useSession, useSetupStatus } from "../features/auth/queries";
import {
  ApiError,
  login,
  setupAdmin,
} from "../lib/api/client";
import { queryKeys } from "../lib/api/queryKeys";

export function LoginPage() {
  const session = useSession();
  const setup = useSetupStatus();
  const queryClient = useQueryClient();
  const navigate = useNavigate();

  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");

  const authMutation = useMutation({
    mutationFn: async () => {
      if (!setup.data?.initialized) {
        if (password !== confirmPassword) {
          throw new Error("两次输入的密码不一致");
        }
        await setupAdmin({ username, password });
      }
      return login({ username, password });
    },
    onSuccess: (nextSession) => {
      queryClient.setQueryData(queryKeys.auth.session(), nextSession);
      queryClient.setQueryData(queryKeys.auth.setup(), { initialized: true });
      navigate("/", { replace: true });
    },
  });

  if (session.data?.authenticated) {
    return <Navigate to="/" replace />;
  }

  const onSubmit = (event: FormEvent) => {
    event.preventDefault();
    authMutation.mutate();
  };

  const message =
    authMutation.error instanceof ApiError
      ? authMutation.error.body?.message ?? authMutation.error.message
      : authMutation.error instanceof Error
        ? authMutation.error.message
        : null;

  const initializing = setup.data?.initialized === false;

  return (
    <div className="auth-screen">
      <div className="auth-card">
        <div className="brand auth-brand">
          <span className="brand-mark">N</span>
          <span>
            <strong>naos</strong>
            <small>{initializing ? "首次初始化" : "登录管理面板"}</small>
          </span>
        </div>

        {setup.isPending ? (
          <div className="inline-state">正在检查初始化状态…</div>
        ) : setup.isError ? (
          <div className="error-box">无法连接 naosd。</div>
        ) : (
          <form onSubmit={onSubmit} className="form-stack">
            <label>
              用户名
              <input
                autoComplete="username"
                value={username}
                onChange={(event) => setUsername(event.target.value)}
                required
              />
            </label>

            <label>
              密码
              <input
                type="password"
                autoComplete={initializing ? "new-password" : "current-password"}
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                required
              />
            </label>

            {initializing && (
              <label>
                确认密码
                <input
                  type="password"
                  autoComplete="new-password"
                  value={confirmPassword}
                  onChange={(event) => setConfirmPassword(event.target.value)}
                  required
                />
              </label>
            )}

            {message && <div className="error-box">{message}</div>}

            <button
              type="submit"
              className="button primary"
              disabled={authMutation.isPending}
            >
              {authMutation.isPending
                ? "处理中…"
                : initializing
                  ? "创建管理员并登录"
                  : "登录"}
            </button>
          </form>
        )}
      </div>
    </div>
  );
}
