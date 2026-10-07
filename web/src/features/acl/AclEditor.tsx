import {
  useMutation,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";
import { useEffect, useMemo, useState } from "react";

import {
  ApiError,
  getOperation,
  listGroups,
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
  const groups = useQuery({
    queryKey: queryKeys.groups.list(),
    queryFn: listGroups,
  });

  const [draft, setDraft] = useState<AclDraftRule[] | null>(null);
  const [operationId, setOperationId] = useState<string | null>(null);

  useEffect(() => {
    if (!acl.data || draft !== null) {
      return;
    }

    setDraft(
      acl.data.items.map((rule) => ({
        key: rule.id,
        rel_path: rule.rel_path,
        subject: {
          type: rule.subject.type,
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
    void queryClient.invalidateQueries({
      queryKey: queryKeys.groups.list(),
    });
    setDraft(null);
    setOperationId(null);
  }, [operation.data?.state, queryClient, shareId]);

  const userMap = useMemo(
    () => new Map(users.data?.items.map((user) => [user.id, user]) ?? []),
    [users.data],
  );
  const groupMap = useMemo(
    () => new Map(groups.data?.items.map((group) => [group.id, group]) ?? []),
    [groups.data],
  );

  const invalidSubject = draft?.some((rule) => {
    if (rule.subject.type === "user") {
      const user = userMap.get(rule.subject.id);
      return !user || !user.enabled;
    }
    if (rule.subject.type === "group") {
      return !groupMap.has(rule.subject.id);
    }
    return true;
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

  const firstUserId = users.data?.items.find((item) => item.enabled)?.id;
  const firstGroupId = groups.data?.items[0]?.id;

  const addRule = () => {
    const subject = firstUserId
      ? { type: "user", id: firstUserId }
      : firstGroupId
        ? { type: "group", id: firstGroupId }
        : null;
    if (!subject) {
      return;
    }

    setDraft((current) => [
      ...(current ?? []),
      {
        key: crypto.randomUUID(),
        rel_path: "/",
        subject,
        permission: "ro",
        inherit: true,
      },
    ]);
  };

  const submit = () => {
    if (!draft || invalidSubject) {
      return;
    }

    save.mutate({
      items: draft.map(({ key: _key, ...rule }) => ({
        ...rule,
        rel_path: rule.rel_path.trim() || "/",
      })),
    });
  };

  const identitiesLoading = users.isPending || groups.isPending;
  const identitiesError = users.isError || groups.isError;
  const hasIdentity = Boolean(firstUserId || firstGroupId);

  return (
    <article className="panel acl-editor-panel">
      <div className="panel-heading">
        <div>
          <h2>ACL</h2>
          <p>
            全量替换 desired ACL，并通过 Operation 同步系统组后落盘 user/group
            filesystem ACL。组身份由不可变 group ID 映射，成员快照会在拿锁后再次验证。
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
            disabled={busy || identitiesLoading || identitiesError || !hasIdentity}
            onClick={addRule}
          >
            添加规则
          </button>
          <button
            className="button primary"
            type="button"
            disabled={busy || draft === null || Boolean(invalidSubject)}
            onClick={submit}
          >
            {save.isPending ? "提交中…" : "保存并 Apply"}
          </button>
        </div>
      </div>

      {acl.isPending || identitiesLoading ? (
        <div className="inline-state settings-state">正在加载 ACL 身份…</div>
      ) : acl.isError ? (
        <div className="error-box settings-error">
          {errorMessage(acl.error)}
        </div>
      ) : users.isError ? (
        <div className="error-box settings-error">
          {errorMessage(users.error)}
        </div>
      ) : groups.isError ? (
        <div className="error-box settings-error">
          {errorMessage(groups.error)}
        </div>
      ) : draft === null ? (
        <div className="inline-state settings-state">正在准备 ACL 草稿…</div>
      ) : (
        <>
          {draft.length === 0 ? (
            <div className="inline-state settings-state">
              当前没有 ACL。保存空列表会移除 naos 管理的 user/group filesystem ACL，
              统一权限语义将回到默认拒绝。
            </div>
          ) : (
            <div className="acl-draft-list">
              {draft.map((rule) => {
                const currentUser =
                  rule.subject.type === "user"
                    ? userMap.get(rule.subject.id)
                    : undefined;
                const currentGroup =
                  rule.subject.type === "group"
                    ? groupMap.get(rule.subject.id)
                    : undefined;

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
                        disabled={busy}
                      />
                    </label>

                    <label>
                      Subject
                      <select
                        value={rule.subject.type}
                        disabled={busy}
                        onChange={(event) => {
                          const type = event.target.value;
                          if (type === "group" && firstGroupId) {
                            updateRule(rule.key, {
                              subject: { type: "group", id: firstGroupId },
                            });
                          } else if (type === "user" && firstUserId) {
                            updateRule(rule.key, {
                              subject: { type: "user", id: firstUserId },
                            });
                          }
                        }}
                      >
                        <option value="user" disabled={!firstUserId}>
                          User
                        </option>
                        <option value="group" disabled={!firstGroupId}>
                          Group
                        </option>
                      </select>
                    </label>

                    <label>
                      Identity
                      {rule.subject.type === "group" ? (
                        <select
                          value={rule.subject.id}
                          disabled={busy}
                          onChange={(event) =>
                            updateRule(rule.key, {
                              subject: {
                                type: "group",
                                id: event.target.value,
                              },
                            })
                          }
                        >
                          {groups.data?.items.map((group) => (
                            <option key={group.id} value={group.id}>
                              {group.name} · {group.member_count} 成员
                            </option>
                          ))}
                        </select>
                      ) : (
                        <select
                          value={rule.subject.id}
                          disabled={busy}
                          onChange={(event) =>
                            updateRule(rule.key, {
                              subject: {
                                type: "user",
                                id: event.target.value,
                              },
                            })
                          }
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
                      )}
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
                        disabled={busy}
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
                        disabled={busy}
                      />
                      <span>继承到子项</span>
                    </label>

                    <button
                      className="button danger"
                      type="button"
                      disabled={busy}
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
                    {rule.subject.type === "group" && !currentGroup && (
                      <div className="warning-box acl-row-warning">
                        用户组不存在；请删除此规则或改选有效用户组。
                      </div>
                    )}
                  </article>
                );
              })}
            </div>
          )}

          {invalidSubject && (
            <div className="warning-box detail-warning">
              ACL 草稿包含不存在、已禁用或无效的 subject，修正后才能保存。
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
