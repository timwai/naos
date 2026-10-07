import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { type FormEvent, useState } from "react";

import { useAuth } from "../features/auth/AuthProvider";
import { api, ApiClientError } from "../lib/api/client";
import { queryKeys } from "../lib/api/queryKeys";

export function ProfilePage() {
  const auth = useAuth();
  const queryClient = useQueryClient();
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [passwordMessage, setPasswordMessage] = useState<string | null>(null);

  const sessions = useQuery({
    queryKey: queryKeys.auth.sessions,
    queryFn: api.sessions,
  });

  const revoke = useMutation({
    mutationFn: api.revokeSession,
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: queryKeys.auth.sessions });
      await auth.refreshSession();
    },
  });

  const changePassword = useMutation({
    mutationFn: api.changePassword,
    onSuccess: () => {
      setCurrentPassword("");
      setNewPassword("");
      setPasswordMessage("密码已更新。");
    },
    onError: (cause) => {
      setPasswordMessage(
        cause instanceof ApiClientError ? cause.message : "密码更新失败。",
      );
    },
  });

  function submitPassword(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setPasswordMessage(null);
    changePassword.mutate({
      current_password: currentPassword,
      new_password: newPassword,
    });
  }

  return (
    <div className="page-stack">
      <section className="page-heading">
        <div>
          <p className="eyebrow">Security</p>
          <h1>个人与会话</h1>
          <p className="muted">
            管理当前账户密码以及服务端保存的登录会话。
          </p>
        </div>
      </section>

      <section className="two-column">
        <article className="panel">
          <div className="panel-heading">
            <div>
              <p className="eyebrow">Password</p>
              <h2>修改密码</h2>
            </div>
          </div>

          <form className="form-stack" onSubmit={submitPassword}>
            <label>
              <span>当前密码</span>
              <input
                autoComplete="current-password"
                required
                type="password"
                value={currentPassword}
                onChange={(event) => setCurrentPassword(event.target.value)}
              />
            </label>
            <label>
              <span>新密码</span>
              <input
                autoComplete="new-password"
                minLength={12}
                required
                type="password"
                value={newPassword}
                onChange={(event) => setNewPassword(event.target.value)}
              />
            </label>

            {passwordMessage ? <div className="notice">{passwordMessage}</div> : null}

            <button
              className="button primary"
              disabled={changePassword.isPending}
              type="submit"
            >
              {changePassword.isPending ? "更新中…" : "更新密码"}
            </button>
          </form>
        </article>

        <article className="panel">
          <div className="panel-heading">
            <div>
              <p className="eyebrow">Sessions</p>
              <h2>登录会话</h2>
            </div>
            <button
              className="button ghost compact"
              type="button"
              onClick={() => void sessions.refetch()}
            >
              刷新
            </button>
          </div>

          {sessions.isPending ? <p className="muted">正在加载会话…</p> : null}
          {sessions.isError ? (
            <div className="inline-error">
              {sessions.error instanceof Error ? sessions.error.message : "会话加载失败"}
            </div>
          ) : null}

          <div className="session-list">
            {sessions.data?.items.map((session) => (
              <article className="session-row" key={session.id}>
                <div>
                  <div className="session-title">
                    <strong>{session.current ? "当前会话" : "登录会话"}</strong>
                    {session.current ? <span className="badge success">CURRENT</span> : null}
                  </div>
                  <span>{session.client_ip ?? "未知地址"}</span>
                  <small>{session.user_agent ?? "未知客户端"}</small>
                  <small>最后活动：{session.last_seen_at}</small>
                </div>
                <button
                  className="button danger compact"
                  disabled={revoke.isPending}
                  type="button"
                  onClick={() => revoke.mutate(session.id)}
                >
                  撤销
                </button>
              </article>
            ))}

            {sessions.data?.items.length === 0 ? (
              <div className="empty-state">没有可显示的会话。</div>
            ) : null}
          </div>
        </article>
      </section>
    </div>
  );
}
