import { useOperation } from "../operations/useOperation";
import {
  useMutation,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";
import { useEffect, useMemo, useState, type FormEvent } from "react";

import {
  ApiError,
  createGroup,
  deleteGroup,
  getGroup,
  listGroups,
  listUsers,
  replaceGroupMembers,
  updateGroup,
} from "../../lib/api/client";
import { queryKeys } from "../../lib/api/queryKeys";

function isTerminal(state: string | undefined) {
  return state === "succeeded" || state === "failed" || state === "degraded";
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

export function GroupManager() {
  const queryClient = useQueryClient();
  const groups = useQuery({
    queryKey: queryKeys.groups.list(),
    queryFn: listGroups,
  });
  const users = useQuery({
    queryKey: queryKeys.users.list(),
    queryFn: listUsers,
  });

  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [createName, setCreateName] = useState("");
  const [createDescription, setCreateDescription] = useState("");
  const [nameDraft, setNameDraft] = useState("");
  const [descriptionDraft, setDescriptionDraft] = useState("");
  const [memberDraft, setMemberDraft] = useState<string[]>([]);
  const [success, setSuccess] = useState<string | null>(null);
  const [operationContext, setOperationContext] = useState<{
    id: string;
    action: "members" | "delete";
    groupId: string;
  } | null>(null);

  useEffect(() => {
    if (
      selectedId &&
      groups.data &&
      !groups.data.items.some((group) => group.id === selectedId)
    ) {
      setSelectedId(null);
    }
  }, [groups.data, selectedId]);

  const detail = useQuery({
    queryKey: queryKeys.groups.detail(selectedId ?? ""),
    queryFn: () => getGroup(selectedId ?? ""),
    enabled: Boolean(selectedId),
  });

  useEffect(() => {
    if (!detail.data) {
      return;
    }
    setNameDraft(detail.data.name);
    setDescriptionDraft(detail.data.description ?? "");
    setMemberDraft(detail.data.members.map((member) => member.id));
  }, [detail.data]);

  const refreshGroup = async (groupId?: string | null) => {
    await queryClient.invalidateQueries({
      queryKey: queryKeys.groups.list(),
    });
    if (groupId) {
      await queryClient.invalidateQueries({
        queryKey: queryKeys.groups.detail(groupId),
      });
    }
    await queryClient.invalidateQueries({
      queryKey: ["groups", "user"],
    });
  };

  const create = useMutation({
    mutationFn: () =>
      createGroup({
        name: createName.trim(),
        description: createDescription.trim() || null,
      }),
    onSuccess: async (group) => {
      setCreateName("");
      setCreateDescription("");
      setSelectedId(group.id);
      setSuccess("用户组已创建");
      await refreshGroup(group.id);
    },
  });

  const update = useMutation({
    mutationFn: () => {
      if (!selectedId) {
        throw new Error("尚未选择用户组");
      }
      return updateGroup(selectedId, {
        name: nameDraft.trim(),
        description: descriptionDraft.trim() || null,
      });
    },
    onSuccess: async (group) => {
      setSuccess("用户组信息已更新");
      await refreshGroup(group.id);
    },
  });

  const members = useMutation({
    mutationFn: () => {
      if (!selectedId) {
        throw new Error("尚未选择用户组");
      }
      return replaceGroupMembers(selectedId, {
        user_ids: memberDraft,
      });
    },
    onSuccess: (accepted) => {
      if (!selectedId) {
        return;
      }
      setOperationContext({
        id: accepted.operation_id,
        action: "members",
        groupId: selectedId,
      });
    },
  });

  const remove = useMutation({
    mutationFn: (groupId: string) => deleteGroup(groupId),
    onSuccess: (accepted, groupId) => {
      setOperationContext({
        id: accepted.operation_id,
        action: "delete",
        groupId,
      });
    },
  });

  const operation = useOperation(operationContext?.id ?? null);

  useEffect(() => {
    if (!operationContext || operation.data?.state !== "succeeded") {
      return;
    }

    const completed = operationContext;
    setOperationContext(null);
    if (completed.action === "delete") {
      setSelectedId(null);
      setSuccess("用户组已删除，系统组也已验证移除");
      void refreshGroup(completed.groupId);
      return;
    }

    setSuccess("成员已同步到系统组并完成数据库提交");
    void refreshGroup(completed.groupId);
  }, [operation.data?.state, operationContext]);

  const operationBusy =
    Boolean(operationContext) && !isTerminal(operation.data?.state);
  const busy =
    create.isPending ||
    update.isPending ||
    members.isPending ||
    remove.isPending ||
    operationBusy;

  const memberSet = useMemo(() => new Set(memberDraft), [memberDraft]);

  const submitCreate = (event: FormEvent) => {
    event.preventDefault();
    if (!createName.trim()) {
      return;
    }
    setSuccess(null);
    create.mutate();
  };

  return (
    <article className="panel group-manager-panel">
      <div className="panel-heading">
        <div>
          <h2>用户组</h2>
          <p>
            成员替换和删除通过 Operation 同步数据库与系统组，并在 verify 后提交。
            系统组身份由不可变 group ID 映射，组改名不会改变 filesystem ACL 身份。
          </p>
        </div>
      </div>

      <form className="group-create-form" onSubmit={submitCreate}>
        <label>
          名称
          <input
            value={createName}
            disabled={busy}
            onChange={(event) => setCreateName(event.target.value)}
            placeholder="family"
          />
        </label>
        <label>
          说明
          <input
            value={createDescription}
            disabled={busy}
            onChange={(event) => setCreateDescription(event.target.value)}
            placeholder="可选"
          />
        </label>
        <button
          className="button primary"
          type="submit"
          disabled={busy || !createName.trim()}
        >
          {create.isPending ? "创建中…" : "创建用户组"}
        </button>
      </form>

      {success && <div className="success-box group-success">{success}</div>}
      {create.isError && <div className="error-box">{errorMessage(create.error)}</div>}
      {update.isError && <div className="error-box">{errorMessage(update.error)}</div>}
      {members.isError && <div className="error-box">{errorMessage(members.error)}</div>}
      {remove.isError && <div className="error-box">{errorMessage(remove.error)}</div>}

      {operation.isError && (
        <div className="error-box">{errorMessage(operation.error)}</div>
      )}
      {operation.data &&
        (operation.data.state === "failed" ||
          operation.data.state === "degraded") && (
          <div className="error-box">
            {operation.data.error_code ?? "GROUP_APPLY_FAILED"}
          </div>
        )}
      {operationContext && operation.data && (
        <div className="share-operation-state group-operation-state">
          <div>
            <strong>
              {operationContext.action === "delete"
                ? "用户组删除"
                : "系统组成员同步"}{" "}
              · {operation.data.state}
            </strong>
            <span>{operation.data.phase ?? "queued"}</span>
          </div>
          <span>{operation.data.progress}%</span>
        </div>
      )}

      {groups.isPending ? (
        <div className="inline-state settings-state">正在加载用户组…</div>
      ) : groups.isError ? (
        <div className="error-box">{errorMessage(groups.error)}</div>
      ) : (
        <div className="group-manager-grid">
          <div className="group-list">
            {groups.data.items.length === 0 ? (
              <div className="inline-state">尚无用户组。</div>
            ) : (
              groups.data.items.map((group) => (
                <button
                  className={
                    selectedId === group.id
                      ? "group-list-item selected"
                      : "group-list-item"
                  }
                  type="button"
                  key={group.id}
                  onClick={() => {
                    setSuccess(null);
                    setSelectedId(group.id);
                  }}
                >
                  <strong>{group.name}</strong>
                  <span>{group.member_count} 位成员</span>
                  {group.description && <small>{group.description}</small>}
                </button>
              ))
            )}
          </div>

          <div className="group-detail">
            {!selectedId ? (
              <div className="inline-state">选择一个用户组管理成员。</div>
            ) : detail.isPending ? (
              <div className="inline-state">正在加载组详情…</div>
            ) : detail.isError ? (
              <div className="error-box">{errorMessage(detail.error)}</div>
            ) : (
              <>
                <div className="group-edit-form">
                  <label>
                    名称
                    <input
                      value={nameDraft}
                      disabled={busy}
                      onChange={(event) => setNameDraft(event.target.value)}
                    />
                  </label>
                  <label>
                    说明
                    <input
                      value={descriptionDraft}
                      disabled={busy}
                      onChange={(event) =>
                        setDescriptionDraft(event.target.value)
                      }
                    />
                  </label>
                  <button
                    className="button secondary"
                    type="button"
                    disabled={busy || !nameDraft.trim()}
                    onClick={() => {
                      setSuccess(null);
                      update.mutate();
                    }}
                  >
                    保存信息
                  </button>
                  <button
                    className="button danger"
                    type="button"
                    disabled={busy}
                    onClick={() => {
                      if (
                        window.confirm(
                          "确定删除用户组 " +
                            detail.data.name +
                            "？仍被 ACL 引用时后端会拒绝。",
                        )
                      ) {
                        setSuccess(null);
                        setOperationContext(null);
                        remove.mutate(detail.data.id);
                      }
                    }}
                  >
                    删除组
                  </button>
                </div>

                <div className="group-members-heading">
                  <div>
                    <strong>成员</strong>
                    <span>{memberDraft.length} / {users.data?.items.length ?? 0}</span>
                  </div>
                  <button
                    className="button primary"
                    type="button"
                    disabled={busy || users.isPending || users.isError}
                    onClick={() => {
                      setSuccess(null);
                      setOperationContext(null);
                      members.mutate();
                    }}
                  >
                    {members.isPending ? "保存中…" : "原子保存成员"}
                  </button>
                </div>

                {users.isPending ? (
                  <div className="inline-state">正在加载用户…</div>
                ) : users.isError ? (
                  <div className="error-box">{errorMessage(users.error)}</div>
                ) : (
                  <div className="group-member-list">
                    {users.data.items.map((user) => (
                      <label className="group-member-row" key={user.id}>
                        <input
                          type="checkbox"
                          checked={memberSet.has(user.id)}
                          disabled={busy}
                          onChange={(event) => {
                            setMemberDraft((current) =>
                              event.target.checked
                                ? [...current, user.id]
                                : current.filter((id) => id !== user.id),
                            );
                          }}
                        />
                        <span>
                          <strong>{user.username}</strong>
                          <small>
                            {user.role} · {user.enabled ? "enabled" : "disabled"}
                          </small>
                        </span>
                      </label>
                    ))}
                  </div>
                )}
              </>
            )}
          </div>
        </div>
      )}
    </article>
  );
}
