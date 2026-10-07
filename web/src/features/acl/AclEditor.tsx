import {
  useMutation,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";
import { useEffect, useMemo, useState } from "react";

import {
  ApiError,
  getOperation,
  listShareAcl,
  listUsers,
  replaceShareAcl,
  type AclReplaceRequest,
} from "../../lib/api/client";
import { queryKeys } from "../../lib/api/queryKeys";

type AclDraftRule = AclReplaceRequest["items"][number] & {
  key: string;
};

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

export function AclEditor({ shareId }: { shareId: string }) {
  const queryClient = useQueryClient();
  const acl = useQuery({
    queryKey: queryKeys.shares.acl(shareId),
    queryFn: () => listShareAcl(shareId),
  });
  const users = useQuery({
    queryKey: queryKeys.users.list(),
    queryFn: listUsers,
  });

  const [draft, setDraft] = useState<AclDraftRule[] | null>(null);
  const [operationId, setOperationId] = useState<string | null>(null);

  const groupRules = useMemo(
    () =>
      acl.data?.items.filter((rule) => rule.subject.type === "group") ?? [],
    [acl.data],
  );

  useEffect(() => {
    if (!acl.data || draft !== null) {
      return;
    }

    setDraft(
      acl.data.items
        .filter((rule) => rule.subject.type === "user")
        .map((rule) => ({
          key: rule.id,
          rel_path: rule.rel_path,
          subject: {
            type: "user",
            id: rule.subject.id,
          },
          permission: rule.permission,
          inherit: rule.inherit,
        })),
    );
  }, [acl.data, draft]);

  const save = useMutation({
    mutationFn: (input: AclReplaceRequest) =>
      replaceShareAcl(shareId, input),
    onSuccess: (operation) => setOperationId(operation.operation_id),
  });

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
      queryKey: queryKeys.shares.acl(shareId),
    });
    void queryClient.invalidateQueries({
      queryKey: queryKeys.shares.detail(shareId),
    });
    void queryClient.invalidateQueries({
      queryKey: queryKeys.shares.list(),
    });
    setDraft(null);
    setOperationId(null);
  }, [operation.data?.state, queryClient, shareId]);

  const userMap = useMemo(
    () => new Map(users.data?.items.map((user) => [user.id, user]) ?? []),
    [users.data],
  );
  const invalidUser = draft?.some((rule) => {
    const user = userMap.get(rule.subject.id);
    return !user || !user.enabled;
  });

  const busy =
    save.isPending ||
    (Boolean(operationId) && !isTerminal(operation.data?.state));

  const updateRule = (
    key: string,
    patch: Partial<Omit<AclDraftRule, "key">>,
  ) => {
    setDraft((current) =>
      current?.map((rule) =>
        rule.key === key ? { ...rule, ...patch } : rule,
      ) ?? [],
    );
  };

  const addRule = () => {
    const user = users.data?.items.find((item) => item.enabled);
    if (!user) {
      return;
    }
    setDraft((current) => [
      ...(current ?? []),
      {
        key: crypto.randomUUID(),
        rel_path: "/",
        subject: { type: "user", id: user.id },
        permission: "ro",
        inherit: true,
      },
    ]);
  };

  const submit = () => {
    if (!draft || groupRules.length > 0 || invalidUser) {
      return;
    }

    save.mutate({
      items: draft.map(({ key: _key, ...rule }) => ({
        ...rule,
        rel_path: rule.rel_path.trim() || "/",
      })),
    });
  };

  return (
    <article className="panel acl-editor-panel">
      <div className="panel-heading">
        <div>
          <h2>ACL</h2>
          <p>
            全量替换 desired ACL，并通过 Operation 将 user ACL 落到文件系统。
            group subject 暂保持只读，直到系统组映射完成。
          </p>
        </div>
        <div className="heading-actions">
          <button
            className="button secondary"
            type="button"
            disabled={busy || draft === null}
            onClick={() => setDraft(null)}
          >
            重置
          </button>
          <button
            className="button secondary"
            type="button"
            disabled={
              busy ||
              users.isPending ||
              !users.data?.items.some((user) => user.enabled) ||
              groupRules.length > 0
            }
            onClick={addRule}
          >
            添加规则
          </button>
          <button
            className="button primary"
            type="button"
            disabled={
              busy ||
              draft === null ||
              groupRules.length > 0 ||
              Boolean(invalidUser)
            }
            onClick={submit}
          >
            {save.isPending ? "提交中…" : "保存并 Apply"}
          </button>
        </div>
      </div>

      {groupRules.length > 0 && (
        <div className="warning-box detail-warning">
          此共享仍包含 {groupRules.length} 条 group ACL。当前版本不会修改这些规则，
          以避免在缺少安全系统组映射时造成权限漂移。
        </div>
      )}

      {acl.isPending || users.isPending ? (
        <div className="inline-state settings-state">正在加载 ACL…</div>
      ) : acl.isError ? (
        <div className="error-box settings-error">
          {errorMessage(acl.error)}
        </div>
      ) : users.isError ? (
        <div className="error-box settings-error">
          {errorMessage(users.error)}
        </div>
      ) : draft === null ? (
        <div className="inline-state settings-state">正在准备 ACL 草稿…</div>
      ) : (
        <>
          {draft.length === 0 ? (
            <div className="inline-state settings-state">
              当前没有 user ACL。保存空列表会移除 naos 管理的 user ACL，
              统一权限语义将回到默认拒绝。
            </div>
          ) : (
            <div className="acl-draft-list">
              {draft.map((rule) => {
                const currentUser = userMap.get(rule.subject.id);
                return (
                  <article className="acl-draft-row" key={rule.key}>
                    <label>
                      相对路径
                      <input
                        value={rule.rel_path}
                        onChange={(event) =>
                          updateRule(rule.key, {
                            rel_path: event.target.value,
                          })
                        }
                        placeholder="/"
                        disabled={busy || groupRules.length > 0}
                      />
                    </label>

                    <label>
                      User
                      <select
                        value={rule.subject.id}
                        onChange={(event) =>
                          updateRule(rule.key, {
                            subject: {
                              type: "user",
                              id: event.target.value,
                            },
                          })
                        }
                        disabled={busy || groupRules.length > 0}
                      >
                        {users.data?.items.map((user) => (
                          <option
                            key={user.id}
                            value={user.id}
                            disabled={!user.enabled}
                          >
                            {user.username}
                            {user.enabled ? "" : " · disabled"}
                          </option>
                        ))}
                      </select>
                    </label>

                    <label>
                      Permission
                      <select
                        value={rule.permission}
                        onChange={(event) =>
                          updateRule(rule.key, {
                            permission: event.target.value,
                          })
                        }
                        disabled={busy || groupRules.length > 0}
                      >
                        <option value="none">拒绝 · none</option>
                        <option value="ro">只读 · ro</option>
                        <option value="rw">读写 · rw</option>
                      </select>
                    </label>

                    <label className="acl-inherit-field">
                      <input
                        type="checkbox"
                        checked={rule.inherit}
                        onChange={(event) =>
                          updateRule(rule.key, {
                            inherit: event.target.checked,
                          })
                        }
                        disabled={busy || groupRules.length > 0}
                      />
                      <span>继承到子项</span>
                    </label>

                    <button
                      className="button danger"
                      type="button"
                      disabled={busy || groupRules.length > 0}
                      onClick={() =>
                        setDraft((current) =>
                          current?.filter((item) => item.key !== rule.key) ??
                          [],
                        )
                      }
                    >
                      删除
                    </button>

                    {currentUser && !currentUser.enabled && (
                      <div className="warning-box acl-row-warning">
                        用户 {currentUser.username} 已禁用；请删除此规则或改选启用用户。
                      </div>
                    )}
                  </article>
                );
              })}
            </div>
          )}

          {invalidUser && (
            <div className="warning-box detail-warning">
              ACL 草稿包含不存在或已禁用的用户，修正后才能保存。
            </div>
          )}
        </>
      )}

      {save.isError && (
        <div className="error-box settings-error">
          {errorMessage(save.error)}
        </div>
      )}
      {operation.isError && (
        <div className="error-box settings-error">
          {errorMessage(operation.error)}
        </div>
      )}
      {operation.data && (
        <div className="share-operation-state acl-operation-state">
          <div>
            <strong>ACL Apply · {operation.data.state}</strong>
            <span>{operation.data.phase ?? "queued"}</span>
          </div>
          <span>{operation.data.progress}%</span>
        </div>
      )}
      {operation.data &&
        (operation.data.state === "failed" ||
          operation.data.state === "degraded") && (
          <div className="error-box settings-error">
            {operation.data.error_code ?? "ACL_APPLY_FAILED"}
          </div>
        )}
    </article>
  );
}
