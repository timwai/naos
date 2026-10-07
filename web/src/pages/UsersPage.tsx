import { useQuery } from "@tanstack/react-query";

import { ApiError, listUsers } from "../lib/api/client";
import { queryKeys } from "../lib/api/queryKeys";

function errorMessage(error: unknown) {
  if (error instanceof ApiError) {
    return error.body?.message ?? error.message;
  }
  if (error instanceof Error) {
    return error.message;
  }
  return "请求失败";
}

export function UsersPage() {
  const users = useQuery({
    queryKey: queryKeys.users.list(),
    queryFn: listUsers,
  });

  const enabled = users.data?.items.filter((user) => user.enabled).length ?? 0;
  const admins =
    users.data?.items.filter((user) => user.role === "admin").length ?? 0;

  return (
    <section>
      <div className="page-heading">
        <div>
          <p className="eyebrow">Identity</p>
          <h1>用户</h1>
          <p>
            当前先接入真实用户目录；创建、禁用与系统账号 Apply 会继续按 Operation 模型补齐。
          </p>
        </div>
        <button
          className="button secondary"
          type="button"
          disabled={users.isFetching}
          onClick={() => users.refetch()}
        >
          {users.isFetching ? "刷新中…" : "刷新"}
        </button>
      </div>

      <div className="metric-grid user-metrics">
        <article className="metric-card">
          <span>用户总数</span>
          <strong>{users.data?.items.length ?? "—"}</strong>
          <small>naos identities</small>
        </article>
        <article className="metric-card">
          <span>已启用</span>
          <strong>{users.data ? enabled : "—"}</strong>
          <small>可用于认证和协议映射</small>
        </article>
        <article className="metric-card">
          <span>管理员</span>
          <strong>{users.data ? admins : "—"}</strong>
          <small>management role</small>
        </article>
      </div>

      <article className="panel">
        <div className="panel-heading">
          <div>
            <h2>用户目录</h2>
            <p>密码和 password hash 永远不会由此接口返回。</p>
          </div>
        </div>

        {users.isPending ? (
          <div className="inline-state settings-state">正在加载用户…</div>
        ) : users.isError ? (
          <div className="error-box settings-error">
            {errorMessage(users.error)}
          </div>
        ) : users.data.items.length === 0 ? (
          <div className="inline-state settings-state">尚无用户。</div>
        ) : (
          <div className="user-list">
            {users.data.items.map((user) => (
              <article className="user-row" key={user.id}>
                <div className="user-avatar" aria-hidden="true">
                  {user.username.slice(0, 1).toUpperCase()}
                </div>
                <div className="user-copy">
                  <div className="user-title">
                    <strong>{user.username}</strong>
                    <span className="role-pill">{user.role}</span>
                    <span
                      className={
                        user.enabled
                          ? "status-pill enabled"
                          : "status-pill disabled"
                      }
                    >
                      {user.enabled ? "enabled" : "disabled"}
                    </span>
                  </div>
                  <span className="mono-copy">{user.id}</span>
                </div>
              </article>
            ))}
          </div>
        )}
      </article>
    </section>
  );
}
