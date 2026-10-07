import {
  useMutation,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";
import { useEffect, useState, type FormEvent } from "react";

import { useSession } from "../features/auth/queries";
import {
  ApiError,
  createUser,
  deleteUser,
  getOperation,
  listUsers,
  resetUserPassword,
  updateUser,
  type UserCreateRequest,
} from "../lib/api/client";
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

function isTerminal(state: string | undefined) {
  return state === "succeeded" || state === "failed" || state === "degraded";
}

const emptyCreate: UserCreateRequest = {
  username: "",
  password: "",
  role: "user",
  enabled: true,
  group_ids: [],
};

export function UsersPage() {
  const queryClient = useQueryClient();
  const session = useSession();
  const users = useQuery({
    queryKey: queryKeys.users.list(),
    queryFn: listUsers,
  });

  const [createDraft, setCreateDraft] = useState<UserCreateRequest>(emptyCreate);
  const [resetUserId, setResetUserId] = useState<string | null>(null);
  const [resetPassword, setResetPassword] = useState("");
  const [operationId, setOperationId] = useState<string | null>(null);
  const [operationLabel, setOperationLabel] = useState("");
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  const operation = useQuery({
    queryKey: queryKeys.operations.detail(operationId ?? ""),
    queryFn: () => getOperation(operationId ?? ""),
    enabled: Boolean(operationId),
    refetchInterval: (query) =>
      isTerminal(query.state.data?.state) ? false : 750,
  });

  useEffect(() => {
    if (operation.data?.state !== "succeeded") {
      return;
    }
    void queryClient.invalidateQueries({
      queryKey: queryKeys.users.list(),
    });
    setSuccessMessage(`${operationLabel}已完成`);
    setOperationId(null);
  }, [operation.data?.state, operationLabel, queryClient]);

  const startOperation = (operationId: string, label: string) => {
    setSuccessMessage(null);
    setOperationLabel(label);
    setOperationId(operationId);
  };

  const create = useMutation({
    mutationFn: (input: UserCreateRequest) => createUser(input),
    onSuccess: (accepted) => {
      setCreateDraft(emptyCreate);
      startOperation(accepted.operation_id, "创建用户");
    },
  });

  const update = useMutation({
    mutationFn: ({
      userId,
      role,
      enabled,
    }: {
      userId: string;
      role: string;
      enabled: boolean;
    }) => updateUser(userId, { role, enabled }),
    onSuccess: (accepted) => startOperation(accepted.operation_id, "更新用户"),
  });

  const reset = useMutation({
    mutationFn: ({ userId, password }: { userId: string; password: string }) =>
      resetUserPassword(userId, { password }),
    onSuccess: (accepted) => {
      setResetUserId(null);
      setResetPassword("");
      startOperation(accepted.operation_id, "重置密码");
    },
  });

  const remove = useMutation({
    mutationFn: (userId: string) => deleteUser(userId),
    onSuccess: (accepted) => startOperation(accepted.operation_id, "删除用户"),
  });

  const busy =
    create.isPending ||
    update.isPending ||
    reset.isPending ||
    remove.isPending ||
    Boolean(operationId);

  const enabled = users.data?.items.filter((user) => user.enabled).length ?? 0;
  const admins =
    users.data?.items.filter((user) => user.role === "admin").length ?? 0;
  const currentUserId = session.data?.user?.id ?? null;

  const submitCreate = (event: FormEvent) => {
    event.preventDefault();
    if (!createDraft.username.trim() || !createDraft.password) {
      return;
    }
    create.mutate({
      ...createDraft,
      username: createDraft.username.trim(),
    });
  };

  return (
    <section>
      <div className="page-heading">
        <div>
          <p className="eyebrow">Identity</p>
          <h1>用户</h1>
          <p>
            用户变更通过持久化 Operation 协调数据库、系统账号与 SMB credential；
            密码不会进入响应、Operation payload 或日志。
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
          <small>可用于管理认证和协议映射</small>
        </article>
        <article className="metric-card">
          <span>管理员</span>
          <strong>{users.data ? admins : "—"}</strong>
          <small>至少保留一个启用管理员</small>
        </article>
      </div>

      <article className="panel user-create-panel">
        <div className="panel-heading">
          <div>
            <h2>创建用户</h2>
            <p>
              新用户会先以 disabled pending identity 写入数据库，系统账号和 credential
              Apply 成功后才按目标状态启用。
            </p>
          </div>
        </div>
        <form className="user-create-form" onSubmit={submitCreate}>
          <label>
            用户名
            <input
              value={createDraft.username}
              autoComplete="off"
              disabled={busy}
              onChange={(event) =>
                setCreateDraft((current) => ({
                  ...current,
                  username: event.target.value,
                }))
              }
              placeholder="alice"
            />
          </label>
          <label>
            初始密码
            <input
              type="password"
              value={createDraft.password}
              autoComplete="new-password"
              disabled={busy}
              onChange={(event) =>
                setCreateDraft((current) => ({
                  ...current,
                  password: event.target.value,
                }))
              }
              placeholder="至少 12 个字符"
            />
          </label>
          <label>
            Role
            <select
              value={createDraft.role}
              disabled={busy}
              onChange={(event) =>
                setCreateDraft((current) => ({
                  ...current,
                  role: event.target.value,
                }))
              }
            >
              <option value="user">user</option>
              <option value="admin">admin</option>
            </select>
          </label>
          <label className="user-enabled-field">
            <input
              type="checkbox"
              checked={createDraft.enabled}
              disabled={busy}
              onChange={(event) =>
                setCreateDraft((current) => ({
                  ...current,
                  enabled: event.target.checked,
                }))
              }
            />
            <span>创建后启用</span>
          </label>
          <button
            className="button primary"
            type="submit"
            disabled={busy || !createDraft.username.trim() || !createDraft.password}
          >
            {create.isPending ? "提交中…" : "创建用户"}
          </button>
        </form>
      </article>

      {successMessage && <div className="success-box">{successMessage}</div>}
      {create.isError && <div className="error-box">{errorMessage(create.error)}</div>}
      {update.isError && <div className="error-box">{errorMessage(update.error)}</div>}
      {reset.isError && <div className="error-box">{errorMessage(reset.error)}</div>}
      {remove.isError && <div className="error-box">{errorMessage(remove.error)}</div>}
      {operation.isError && (
        <div className="error-box">{errorMessage(operation.error)}</div>
      )}
      {operation.data && (
        <div className="share-operation-state user-operation-state">
          <div>
            <strong>
              {operationLabel} · {operation.data.state}
            </strong>
            <span>{operation.data.phase ?? "queued"}</span>
          </div>
          <span>{operation.data.progress}%</span>
        </div>
      )}
      {operation.data &&
        (operation.data.state === "failed" ||
          operation.data.state === "degraded") && (
          <div className="error-box">
            {operation.data.error_code ?? "USER_OPERATION_FAILED"}
          </div>
        )}

      <article className="panel">
        <div className="panel-heading">
          <div>
            <h2>用户目录</h2>
            <p>
              删除会拒绝仍被共享 ACL 引用的用户；当前登录管理员不能禁用、降级或删除自己。
            </p>
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
            {users.data.items.map((user) => {
              const isSelf = user.id === currentUserId;
              const resetting = resetUserId === user.id;
              return (
                <article className="user-row user-admin-row" key={user.id}>
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
                      {isSelf && <span className="role-pill">当前用户</span>}
                    </div>
                    <span className="mono-copy">{user.id}</span>

                    {resetting && (
                      <div className="user-password-reset">
                        <input
                          type="password"
                          autoComplete="new-password"
                          value={resetPassword}
                          disabled={busy}
                          onChange={(event) =>
                            setResetPassword(event.target.value)
                          }
                          placeholder="新密码（至少 12 个字符）"
                        />
                        <button
                          className="button primary"
                          type="button"
                          disabled={busy || !resetPassword}
                          onClick={() =>
                            reset.mutate({
                              userId: user.id,
                              password: resetPassword,
                            })
                          }
                        >
                          提交重置
                        </button>
                        <button
                          className="button secondary"
                          type="button"
                          disabled={busy}
                          onClick={() => {
                            setResetUserId(null);
                            setResetPassword("");
                          }}
                        >
                          取消
                        </button>
                      </div>
                    )}
                  </div>

                  <div className="user-actions">
                    <button
                      className="button secondary"
                      type="button"
                      disabled={busy || isSelf}
                      onClick={() =>
                        update.mutate({
                          userId: user.id,
                          role: user.role === "admin" ? "user" : "admin",
                          enabled: user.enabled,
                        })
                      }
                    >
                      {user.role === "admin" ? "降为 user" : "升为 admin"}
                    </button>
                    <button
                      className="button secondary"
                      type="button"
                      disabled={busy || isSelf}
                      onClick={() =>
                        update.mutate({
                          userId: user.id,
                          role: user.role,
                          enabled: !user.enabled,
                        })
                      }
                    >
                      {user.enabled ? "禁用" : "启用"}
                    </button>
                    <button
                      className="button secondary"
                      type="button"
                      disabled={busy}
                      onClick={() => {
                        setResetUserId(user.id);
                        setResetPassword("");
                      }}
                    >
                      重置密码
                    </button>
                    <button
                      className="button danger"
                      type="button"
                      disabled={busy || isSelf}
                      onClick={() => {
                        if (
                          window.confirm(
                            `确定删除用户 ${user.username}？仍被 ACL 引用时后端会拒绝此操作。`,
                          )
                        ) {
                          remove.mutate(user.id);
                        }
                      }}
                    >
                      删除
                    </button>
                  </div>
                </article>
              );
            })}
          </div>
        )}
      </article>
    </section>
  );
}
