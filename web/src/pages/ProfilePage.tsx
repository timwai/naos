import {
  useMutation,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";
import { useState, type FormEvent } from "react";

import { useSession } from "../features/auth/queries";
import {
  ApiError,
  changePassword,
  listSessions,
  revokeSession,
} from "../lib/api/client";
import { queryKeys } from "../lib/api/queryKeys";

function formatTimestamp(value: string) {
  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? value
    : new Intl.DateTimeFormat("zh-CN", {
        dateStyle: "medium",
        timeStyle: "short",
      }).format(date);
}

function errorMessage(error: unknown) {
  if (error instanceof ApiError) {
    return error.body?.message ?? error.message;
  }
  if (error instanceof Error) {
    return error.message;
  }
  return "请求失败";
}

export function ProfilePage() {
  const session = useSession();
  const queryClient = useQueryClient();
  const sessions = useQuery({
    queryKey: queryKeys.auth.sessions(),
    queryFn: listSessions,
  });

  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [passwordSaved, setPasswordSaved] = useState(false);

  const passwordMutation = useMutation({
    mutationFn: async () => {
      if (newPassword !== confirmPassword) {
        throw new Error("两次输入的新密码不一致");
      }
      await changePassword({
        current_password: currentPassword,
        new_password: newPassword,
      });
    },
    onSuccess: async () => {
      setCurrentPassword("");
      setNewPassword("");
      setConfirmPassword("");
      setPasswordSaved(true);
      await queryClient.invalidateQueries({
        queryKey: queryKeys.auth.sessions(),
      });
    },
  });

  const revokeMutation = useMutation({
    mutationFn: revokeSession,
    onSuccess: async () => {
      await queryClient.invalidateQueries({
        queryKey: queryKeys.auth.sessions(),
      });
    },
  });

  const submitPassword = (event: FormEvent) => {
    event.preventDefault();
    setPasswordSaved(false);
    passwordMutation.mutate();
  };

  return (
    <section>
      <div className="page-heading">
        <div>
          <p className="eyebrow">Account security</p>
          <h1>个人安全</h1>
          <p>
            当前用户：{session.data?.user?.username ?? "—"}。密码和会话操作都直接调用 naosd。
          </p>
        </div>
      </div>

      <div className="profile-grid">
        <article className="panel profile-panel">
          <div className="panel-heading">
            <div>
              <h2>修改密码</h2>
              <p>服务端负责密码策略和当前密码校验。</p>
            </div>
          </div>

          <form className="form-stack" onSubmit={submitPassword}>
            <label>
              当前密码
              <input
                type="password"
                autoComplete="current-password"
                value={currentPassword}
                onChange={(event) => setCurrentPassword(event.target.value)}
                required
              />
            </label>

            <label>
              新密码
              <input
                type="password"
                autoComplete="new-password"
                value={newPassword}
                onChange={(event) => setNewPassword(event.target.value)}
                required
              />
            </label>

            <label>
              确认新密码
              <input
                type="password"
                autoComplete="new-password"
                value={confirmPassword}
                onChange={(event) => setConfirmPassword(event.target.value)}
                required
              />
            </label>

            {passwordMutation.isError && (
              <div className="error-box">
                {errorMessage(passwordMutation.error)}
              </div>
            )}
            {passwordSaved && (
              <div className="success-box">密码已更新。</div>
            )}

            <button
              className="button primary"
              type="submit"
              disabled={passwordMutation.isPending}
            >
              {passwordMutation.isPending ? "更新中…" : "更新密码"}
            </button>
          </form>
        </article>

        <article className="panel profile-panel session-panel">
          <div className="panel-heading">
            <div>
              <h2>登录会话</h2>
              <p>撤销其它设备的会话会立即使对应 Cookie 失效。</p>
            </div>
            {sessions.data && (
              <span>{sessions.data.items.length} 个</span>
            )}
          </div>

          {sessions.isPending ? (
            <div className="inline-state">正在加载会话…</div>
          ) : sessions.isError ? (
            <div className="error-box">{errorMessage(sessions.error)}</div>
          ) : sessions.data.items.length === 0 ? (
            <div className="inline-state">没有活动会话。</div>
          ) : (
            <div className="session-list">
              {sessions.data.items.map((item) => (
                <article className="session-row" key={item.id}>
                  <div className="session-copy">
                    <div className="session-title">
                      <strong>
                        {item.user_agent || "未知客户端"}
                      </strong>
                      {item.current && (
                        <span className="role-pill">当前会话</span>
                      )}
                    </div>
                    <dl className="session-meta">
                      <div>
                        <dt>IP</dt>
                        <dd>{item.client_ip || "未知"}</dd>
                      </div>
                      <div>
                        <dt>最近活动</dt>
                        <dd>{formatTimestamp(item.last_seen_at)}</dd>
                      </div>
                      <div>
                        <dt>到期</dt>
                        <dd>{formatTimestamp(item.expires_at)}</dd>
                      </div>
                    </dl>
                  </div>

                  {!item.current && (
                    <button
                      type="button"
                      className="button danger"
                      disabled={revokeMutation.isPending}
                      onClick={() => revokeMutation.mutate(item.id)}
                    >
                      撤销
                    </button>
                  )}
                </article>
              ))}
            </div>
          )}

          {revokeMutation.isError && (
            <div className="error-box session-error">
              {errorMessage(revokeMutation.error)}
            </div>
          )}
        </article>
      </div>
    </section>
  );
}
