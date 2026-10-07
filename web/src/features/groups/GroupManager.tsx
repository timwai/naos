import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
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
  type GroupWriteRequest,
} from "../../lib/api/client";
import { queryKeys } from "../../lib/api/queryKeys";

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

  const [selectedGroupId, setSelectedGroupId] = useState<string | null>(null);
  const [createName, setCreateName] = useState("");
  const [createDescription, setCreateDescription] = useState("");
  const [editName, setEditName] = useState("");
  const [editDescription, setEditDescription] = useState("");
  const [memberIds, setMemberIds] = useState<string[]>([]);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  const detail = useQuery({
    queryKey: queryKeys.groups.detail(selectedGroupId ?? ""),
    queryFn: () => getGroup(selectedGroupId ?? ""),
    enabled: Boolean(selectedGroupId),
  });

  useEffect(() => {
    if (!detail.data) {
      return;
    }
    setEditName(detail.data.name);
    setEditDescription(detail.data.description ?? "");
    setMemberIds(detail.data.members.map((member) => member.id));
  }, [detail.data]);

  const refreshGroupQueries = async () => {
    await queryClient.invalidateQueries({ queryKey: ["groups"] });
  };

  const create = useMutation({
    mutationFn: (input: GroupWriteRequest) => createGroup(input),
    onSuccess: async (group) => {
      setCreateName("");
      setCreateDescription("");
      setSelectedGroupId(group.id);
      setSuccessMessage(`已创建用户组 ${group.name}`);
      await refreshGroupQueries();
    },
  });

  const update = useMutation({
    mutationFn: () =>
      updateGroup(selectedGroupId ?? "", {
        name: editName.trim(),
        description: editDescription.trim() || null,
      }),
    onSuccess: async (group) => {
      setSuccessMessage(`已更新用户组 ${group.name}`);
      await refreshGroupQueries();
    },
  });

  const replaceMembers = useMutation({
    mutationFn: () =>
      replaceGroupMembers(selectedGroupId ?? "", {
        user_ids: memberIds,
      }),
    onSuccess: async (group) => {
      setSuccessMessage(`已保存 ${group.name} 的成员关系`);
      await refreshGroupQueries();
    },
  });

  const remove = useMutation({
    mutationFn: (groupId: string) => deleteGroup(groupId),
    onSuccess: async () => {
      setSelectedGroupId(null);
      setEditName("");
      setEditDescription("");
      setMemberIds([]);
      setSuccessMessage("用户组已删除");
      await refreshGroupQueries();
    },
  });

  const busy =
    create.isPending ||
    update.isPending ||
    replaceMembers.isPending ||
    remove.isPending;

  const memberSet = useMemo(() => new Set(memberIds), [memberIds]);

  const submitCreate = (event: FormEvent) => {
    event.preventDefault();
    const name = createName.trim();
    if (!name) {
      return;
    }
    setSuccessMessage(null);
    create.mutate({
      name,
      description: createDescription.trim() || null,
    });
  };

  const toggleMember = (userId: string, checked: boolean) => {
    setMemberIds((current) => {
      if (checked) {
        return current.includes(userId) ? current : [...current, userId];
      }
      return current.filter((id) => id !== userId);
    });
  };

  const requestDelete = () => {
    if (!selectedGroupId || !detail.data) {
      return;
    }
    if (
      window.confirm(
        `确定删除用户组 ${detail.data.name}？仍被共享 ACL 引用时后端会拒绝删除。`,
      )
    ) {
      setSuccessMessage(null);
      remove.mutate(selectedGroupId);
    }
  };

  return (
    <article className="panel group-manager">
      <div className="panel-heading">
        <div>
          <h2>用户组</h2>
          <p>
            用户组用于统一 ACL 身份；成员替换为原子操作。group ACL 的文件系统落盘仍保持
            fail-closed，直到安全系统组映射完成。
          </p>
        </div>
        <button
          className="button secondary"
          type="button"
          disabled={groups.isFetching || busy}
          onClick={() => groups.refetch()}
        >
          {groups.isFetching ? "刷新中…" : "刷新用户组"}
        </button>
      </div>

      <form className="group-create-form" onSubmit={submitCreate}>
        <label>
          组名
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
            placeholder="家庭成员"
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

      {successMessage && <div className="success-box group-feedback">{successMessage}</div>}
      {create.isError && (
        <div className="error-box group-feedback">{errorMessage(create.error)}</div>
      )}
      {update.isError && (
        <div className="error-box group-feedback">{errorMessage(update.error)}</div>
      )}
      {replaceMembers.isError && (
        <div className="error-box group-feedback">
          {errorMessage(replaceMembers.error)}
        </div>
      )}
      {remove.isError && (
        <div className="error-box group-feedback">{errorMessage(remove.error)}</div>
      )}

      <div className="group-management-grid">
        <section className="group-catalog">
          <div className="group-section-heading">
            <strong>组目录</strong>
            <span>{groups.data?.items.length ?? "—"} 个</span>
          </div>

          {groups.isPending ? (
            <div className="inline-state settings-state">正在加载用户组…</div>
          ) : groups.isError ? (
            <div className="error-box settings-error">{errorMessage(groups.error)}</div>
          ) : groups.data.items.length === 0 ? (
            <div className="inline-state settings-state">尚未创建用户组。</div>
          ) : (
            <div className="group-list">
              {groups.data.items.map((group) => (
                <button
                  key={group.id}
                  className={
                    selectedGroupId === group.id
                      ? "group-list-item selected"
                      : "group-list-item"
                  }
                  type="button"
                  disabled={busy}
                  onClick={() => {
                    setSuccessMessage(null);
                    setSelectedGroupId(group.id);
                  }}
                >
                  <span>
                    <strong>{group.name}</strong>
                    <small>{group.description || "无说明"}</small>
                  </span>
                  <span className="role-pill">{group.member_count} 成员</span>
                </button>
              ))}
            </div>
          )}
        </section>

        <section className="group-detail-editor">
          {!selectedGroupId ? (
            <div className="inline-state settings-state">
              选择一个用户组以编辑名称、说明和成员。
            </div>
          ) : detail.isPending ? (
            <div className="inline-state settings-state">正在加载用户组详情…</div>
          ) : detail.isError ? (
            <div className="error-box settings-error">{errorMessage(detail.error)}</div>
          ) : (
            <>
              <div className="group-section-heading">
                <div>
                  <strong>{detail.data.name}</strong>
                  <span className="mono-copy">{detail.data.id}</span>
                </div>
                <button
                  className="button danger"
                  type="button"
                  disabled={busy}
                  onClick={requestDelete}
                >
                  {remove.isPending ? "删除中…" : "删除用户组"}
                </button>
              </div>

              <form
                className="group-edit-form"
                onSubmit={(event) => {
                  event.preventDefault();
                  if (!editName.trim()) {
                    return;
                  }
                  setSuccessMessage(null);
                  update.mutate();
                }}
              >
                <label>
                  组名
                  <input
                    value={editName}
                    disabled={busy}
                    onChange={(event) => setEditName(event.target.value)}
                  />
                </label>
                <label>
                  说明
                  <input
                    value={editDescription}
                    disabled={busy}
                    onChange={(event) => setEditDescription(event.target.value)}
                  />
                </label>
                <button
                  className="button secondary"
                  type="submit"
                  disabled={busy || !editName.trim()}
                >
                  {update.isPending ? "保存中…" : "保存组信息"}
                </button>
              </form>

              <div className="group-members-heading">
                <div>
                  <strong>成员</strong>
                  <span>{memberIds.length} 个已选择</span>
                </div>
                <button
                  className="button primary"
                  type="button"
                  disabled={busy || users.isPending || users.isError}
                  onClick={() => {
                    setSuccessMessage(null);
                    replaceMembers.mutate();
                  }}
                >
                  {replaceMembers.isPending ? "保存中…" : "保存成员"}
                </button>
              </div>

              {users.isPending ? (
                <div className="inline-state settings-state">正在加载用户…</div>
              ) : users.isError ? (
                <div className="error-box settings-error">{errorMessage(users.error)}</div>
              ) : (
                <div className="group-member-grid">
                  {users.data.items.map((user) => (
                    <label className="group-member-option" key={user.id}>
                      <input
                        type="checkbox"
                        checked={memberSet.has(user.id)}
                        disabled={busy}
                        onChange={(event) =>
                          toggleMember(user.id, event.target.checked)
                        }
                      />
                      <span>
                        <strong>{user.username}</strong>
                        <small>
                          {user.role} · {user.enabled ? "enabled" : "disabled"}
                        </small>
                      </span>
                    </label>
                  ))}
                  {users.data.items.length === 0 && (
                    <div className="inline-state settings-state">尚无可分配用户。</div>
                  )}
                </div>
              )}
            </>
          )}
        </section>
      </div>
    </article>
  );
}
