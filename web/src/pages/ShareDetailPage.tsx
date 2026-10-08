import { useOperation } from "../features/operations/useOperation";
import {
  useMutation,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";
import { useEffect, useState, type FormEvent } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";

import { AclEditor } from "../features/acl/AclEditor";
import {
  ApiError,
  createNfsBinding,
  deleteNfsBinding,
  deleteShare,
  getShare,
  listNfsBindings,
  listShareAcl,
  listUsers,
  updateNfsBinding,
  updateShare,
  type NfsBindingDto,
  type NfsBindingUpsertRequest,
  type ShareWriteRequest,
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

export function ShareDetailPage() {
  const { id = "" } = useParams();
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  const share = useQuery({
    queryKey: queryKeys.shares.detail(id),
    queryFn: () => getShare(id),
    enabled: Boolean(id),
  });
  const bindings = useQuery({
    queryKey: queryKeys.nfs.bindings(id),
    queryFn: () => listNfsBindings(id),
    enabled: Boolean(id),
  });
  const acl = useQuery({
    queryKey: queryKeys.shares.acl(id),
    queryFn: () => listShareAcl(id),
    enabled: Boolean(id),
  });
  const users = useQuery({
    queryKey: queryKeys.users.list(),
    queryFn: listUsers,
  });

  const [editingId, setEditingId] = useState<string | null>(null);
  const [cidr, setCidr] = useState("");
  const [uid, setUid] = useState("");
  const [userId, setUserId] = useState("");
  const [permission, setPermission] = useState("ro");
  const [configDraft, setConfigDraft] = useState<ShareWriteRequest | null>(
    null,
  );
  const [shareOperationId, setShareOperationId] = useState<string | null>(
    null,
  );
  const [shareAction, setShareAction] = useState<"update" | "delete" | null>(
    null,
  );

  const selectedUserId =
    userId || users.data?.items.find((user) => user.enabled)?.id || "";

  const resetForm = () => {
    setEditingId(null);
    setCidr("");
    setUid("");
    setUserId("");
    setPermission("ro");
  };

  const saveShare = useMutation({
    mutationFn: (input: ShareWriteRequest) => updateShare(id, input),
    onSuccess: (operation) => {
      setShareAction("update");
      setShareOperationId(operation.operation_id);
    },
  });

  const removeShare = useMutation({
    mutationFn: () => deleteShare(id),
    onSuccess: (operation) => {
      setShareAction("delete");
      setShareOperationId(operation.operation_id);
    },
  });

  const shareOperation = useOperation(shareOperationId);

  useEffect(() => {
    if (!share.data || configDraft !== null) {
      return;
    }
    setConfigDraft({
      name: share.data.name,
      path: share.data.path,
      comment: share.data.comment,
      enabled: share.data.enabled,
      smb_enabled: share.data.smb_enabled,
      webdav_enabled: share.data.webdav_enabled,
      nfs_enabled: share.data.nfs_enabled,
    });
  }, [configDraft, share.data]);

  useEffect(() => {
    if (shareOperation.data?.state !== "succeeded") {
      return;
    }

    if (shareAction === "delete") {
      void queryClient.invalidateQueries({
        queryKey: queryKeys.shares.list(),
      });
      navigate("/shares", { replace: true });
      return;
    }

    if (shareAction === "update") {
      void queryClient.invalidateQueries({
        queryKey: queryKeys.shares.detail(id),
      });
      void queryClient.invalidateQueries({
        queryKey: queryKeys.shares.list(),
      });
      setShareOperationId(null);
      setShareAction(null);
    }
  }, [
    id,
    navigate,
    queryClient,
    shareAction,
    shareOperation.data?.state,
  ]);

  const saveBinding = useMutation({
    mutationFn: async () => {
      const trimmedUid = uid.trim();
      const parsedUid =
        trimmedUid === "" ? null : Number.parseInt(trimmedUid, 10);

      if (
        parsedUid !== null &&
        (!Number.isSafeInteger(parsedUid) || parsedUid < 0)
      ) {
        throw new Error("UID 必须是非负整数");
      }

      const input: NfsBindingUpsertRequest = {
        cidr: cidr.trim(),
        uid: parsedUid,
        user_id: selectedUserId,
        permission,
      };

      if (editingId) {
        return updateNfsBinding(id, editingId, input);
      }
      return createNfsBinding(id, input);
    },
    onSuccess: async () => {
      resetForm();
      await queryClient.invalidateQueries({
        queryKey: queryKeys.nfs.bindings(id),
      });
    },
  });

  const removeBinding = useMutation({
    mutationFn: (bindingId: string) => deleteNfsBinding(id, bindingId),
    onSuccess: async () => {
      await queryClient.invalidateQueries({
        queryKey: queryKeys.nfs.bindings(id),
      });
    },
  });

  const beginEdit = (binding: NfsBindingDto) => {
    setEditingId(binding.id);
    setCidr(binding.cidr);
    setUid(binding.uid === null ? "" : String(binding.uid));
    setUserId(binding.user_id);
    setPermission(binding.permission);
    saveBinding.reset();
  };

  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (!cidr.trim() || !selectedUserId) {
      return;
    }
    saveBinding.mutate();
  };

  const submitShare = (event: FormEvent) => {
    event.preventDefault();
    if (!configDraft) {
      return;
    }
    setShareOperationId(null);
    setShareAction(null);
    saveShare.mutate({
      ...configDraft,
      name: configDraft.name.trim(),
      path: configDraft.path.trim(),
      comment: configDraft.comment?.trim() || null,
    });
  };

  const requestDelete = () => {
    if (
      window.confirm(
        "确定删除此共享？外部 SMB 清理成功后，数据库记录、ACL 与 NFS binding 会一起删除。",
      )
    ) {
      setShareOperationId(null);
      setShareAction(null);
      removeShare.mutate();
    }
  };

  if (!id) {
    return <div className="error-box">共享 ID 无效。</div>;
  }

  if (share.isPending) {
    return <div className="center-state">正在加载共享…</div>;
  }

  if (share.isError) {
    return <div className="error-box">{errorMessage(share.error)}</div>;
  }

  const protocols = [
    share.data.smb_enabled ? "SMB" : null,
    share.data.webdav_enabled ? "WebDAV" : null,
    share.data.nfs_enabled ? "NFS" : null,
  ].filter((item): item is string => Boolean(item));

  return (
    <section>
      <div className="detail-back">
        <Link to="/shares">← 返回共享</Link>
      </div>

      <div className="page-heading detail-heading">
        <div>
          <p className="eyebrow">Share detail</p>
          <h1>{share.data.name}</h1>
          <p className="share-path">{share.data.path}</p>
        </div>
        <div className="detail-status">
          <span
            className={
              share.data.enabled
                ? "status-pill enabled"
                : "status-pill disabled"
            }
          >
            {share.data.enabled ? "enabled" : "disabled"}
          </span>
          <span className={"apply-pill " + share.data.apply_state}>
            {share.data.apply_state}
          </span>
        </div>
      </div>

      <div className="detail-metrics">
        <article className="metric-card">
          <span>协议</span>
          <strong>{protocols.join(" · ") || "none"}</strong>
          <small>desired protocol state</small>
        </article>
        <article className="metric-card">
          <span>Generation</span>
          <strong>
            {share.data.applied_generation}/{share.data.generation}
          </strong>
          <small>applied / desired</small>
        </article>
        <article className="metric-card">
          <span>ACL</span>
          <strong>{acl.data?.items.length ?? "—"}</strong>
          <small>persisted rules</small>
        </article>
      </div>

      <article className="panel share-config-detail">
        <div className="panel-heading">
          <div>
            <h2>共享配置</h2>
            <p>
              保存后先更新 desired state 与 generation，再由 Operation/Reconciler 应用协议状态。
            </p>
          </div>
          <button
            className="button danger"
            type="button"
            disabled={
              removeShare.isPending ||
              (Boolean(shareOperationId) &&
                !isTerminal(shareOperation.data?.state))
            }
            onClick={requestDelete}
          >
            {removeShare.isPending ? "提交删除…" : "删除共享"}
          </button>
        </div>

        {configDraft && (
          <form className="share-config-form" onSubmit={submitShare}>
            <label>
              名称
              <input
                value={configDraft.name}
                onChange={(event) =>
                  setConfigDraft((value) =>
                    value
                      ? { ...value, name: event.target.value }
                      : value,
                  )
                }
                required
              />
            </label>
            <label>
              宿主路径
              <input
                value={configDraft.path}
                onChange={(event) =>
                  setConfigDraft((value) =>
                    value
                      ? { ...value, path: event.target.value }
                      : value,
                  )
                }
                required
              />
            </label>
            <label className="share-config-comment">
              说明
              <input
                value={configDraft.comment ?? ""}
                onChange={(event) =>
                  setConfigDraft((value) =>
                    value
                      ? { ...value, comment: event.target.value }
                      : value,
                  )
                }
              />
            </label>

            <div className="share-toggle-grid">
              <label className="toggle-field">
                <input
                  type="checkbox"
                  checked={configDraft.enabled}
                  onChange={(event) =>
                    setConfigDraft((value) =>
                      value
                        ? { ...value, enabled: event.target.checked }
                        : value,
                    )
                  }
                />
                <span>启用共享</span>
              </label>
              <label className="toggle-field">
                <input
                  type="checkbox"
                  checked={configDraft.smb_enabled}
                  onChange={(event) =>
                    setConfigDraft((value) =>
                      value
                        ? { ...value, smb_enabled: event.target.checked }
                        : value,
                    )
                  }
                />
                <span>SMB</span>
              </label>
              <label className="toggle-field">
                <input
                  type="checkbox"
                  checked={configDraft.webdav_enabled}
                  onChange={(event) =>
                    setConfigDraft((value) =>
                      value
                        ? { ...value, webdav_enabled: event.target.checked }
                        : value,
                    )
                  }
                />
                <span>WebDAV</span>
              </label>
              <label className="toggle-field">
                <input
                  type="checkbox"
                  checked={configDraft.nfs_enabled}
                  onChange={(event) =>
                    setConfigDraft((value) =>
                      value
                        ? { ...value, nfs_enabled: event.target.checked }
                        : value,
                    )
                  }
                />
                <span>NFS</span>
              </label>
            </div>

            {saveShare.isError && (
              <div className="error-box">{errorMessage(saveShare.error)}</div>
            )}
            {removeShare.isError && (
              <div className="error-box">
                {errorMessage(removeShare.error)}
              </div>
            )}
            {shareOperation.isError && (
              <div className="error-box">
                {errorMessage(shareOperation.error)}
              </div>
            )}
            {shareOperation.data && (
              <div className="share-operation-state">
                <div>
                  <strong>
                    {shareAction === "delete" ? "删除" : "更新"} ·{" "}
                    {shareOperation.data.state}
                  </strong>
                  <span>{shareOperation.data.phase ?? "queued"}</span>
                </div>
                <span>{shareOperation.data.progress}%</span>
              </div>
            )}
            {shareOperation.data &&
              (shareOperation.data.state === "failed" ||
                shareOperation.data.state === "degraded") && (
                <div className="error-box">
                  {shareOperation.data.error_code ?? "SHARE_APPLY_FAILED"}
                </div>
              )}

            <button
              className="button primary"
              type="submit"
              disabled={
                saveShare.isPending ||
                (Boolean(shareOperationId) &&
                  !isTerminal(shareOperation.data?.state))
              }
            >
              {saveShare.isPending ? "提交中…" : "保存并 Apply"}
            </button>
          </form>
        )}
      </article>

      {share.data.comment && (
        <article className="panel detail-comment">{share.data.comment}</article>
      )}

      <AclEditor shareId={id} />

      <div className="detail-grid">
        <article className="panel detail-panel">
          <div className="panel-heading">
            <div>
              <h2>NFS L1/L2 bindings</h2>
              <p>
                L1 使用 CIDR → user；填写 UID 后自动成为 L2 CIDR + UID → user。
              </p>
            </div>
            {bindings.data && <span>{bindings.data.items.length} 条</span>}
          </div>

          {bindings.isPending ? (
            <div className="inline-state settings-state">
              正在加载 NFS bindings…
            </div>
          ) : bindings.isError ? (
            <div className="error-box settings-error">
              {errorMessage(bindings.error)}
            </div>
          ) : bindings.data.items.length === 0 ? (
            <div className="inline-state settings-state">
              尚未配置 L1/L2 binding。
            </div>
          ) : (
            <div className="binding-list">
              {bindings.data.items.map((binding) => (
                <article className="binding-row" key={binding.id}>
                  <div className="binding-copy">
                    <div className="binding-title">
                      <strong>{binding.cidr}</strong>
                      <span className="role-pill">
                        {binding.level.toUpperCase()}
                      </span>
                      <span className="permission-pill">
                        {binding.permission}
                      </span>
                    </div>
                    <span>
                      user {binding.user_id}
                      {binding.uid === null ? "" : ` · uid ${binding.uid}`}
                    </span>
                  </div>
                  <div className="binding-actions">
                    <button
                      type="button"
                      className="button secondary"
                      onClick={() => beginEdit(binding)}
                    >
                      编辑
                    </button>
                    <button
                      type="button"
                      className="button danger"
                      disabled={removeBinding.isPending}
                      onClick={() => removeBinding.mutate(binding.id)}
                    >
                      删除
                    </button>
                  </div>
                </article>
              ))}
            </div>
          )}

          {removeBinding.isError && (
            <div className="error-box settings-error">
              {errorMessage(removeBinding.error)}
            </div>
          )}
        </article>

        <article className="panel detail-panel">
          <div className="panel-heading">
            <div>
              <h2>{editingId ? "编辑 binding" : "添加 binding"}</h2>
              <p>
                CIDR 与 UID 的规范化、重复冲突和用户有效性由后端最终校验。
              </p>
            </div>
            {editingId && (
              <button
                type="button"
                className="button secondary"
                onClick={resetForm}
              >
                取消编辑
              </button>
            )}
          </div>

          {!share.data.nfs_enabled && (
            <div className="warning-box detail-warning">
              当前共享未启用 NFS。先完成 Share 协议配置后再新增 binding。
            </div>
          )}

          <form className="form-stack detail-form" onSubmit={submit}>
            <label>
              CIDR
              <input
                placeholder="192.168.1.0/24"
                value={cidr}
                onChange={(event) => setCidr(event.target.value)}
                required
                disabled={!share.data.nfs_enabled}
              />
            </label>
            <label>
              UID（留空为 L1）
              <input
                type="number"
                min="0"
                step="1"
                placeholder="1000"
                value={uid}
                onChange={(event) => setUid(event.target.value)}
                disabled={!share.data.nfs_enabled}
              />
            </label>
            <label>
              User
              <select
                value={selectedUserId}
                onChange={(event) => setUserId(event.target.value)}
                required
                disabled={
                  !share.data.nfs_enabled || users.isPending || users.isError
                }
              >
                {users.data?.items.some((user) => user.enabled) ? null : (
                  <option value="">没有已启用用户</option>
                )}
                {users.data?.items
                  .filter((user) => user.enabled)
                  .map((user) => (
                    <option key={user.id} value={user.id}>
                      {user.username} · {user.role}
                    </option>
                  ))}
              </select>
            </label>
            <label>
              Permission
              <select
                value={permission}
                onChange={(event) => setPermission(event.target.value)}
                disabled={!share.data.nfs_enabled}
              >
                <option value="ro">只读 · ro</option>
                <option value="rw">读写 · rw</option>
              </select>
            </label>

            {saveBinding.isError && (
              <div className="error-box">
                {errorMessage(saveBinding.error)}
              </div>
            )}

            <button
              type="submit"
              className="button primary"
              disabled={
                !share.data.nfs_enabled ||
                !cidr.trim() ||
                !selectedUserId ||
                saveBinding.isPending
              }
            >
              {saveBinding.isPending
                ? "保存中…"
                : editingId
                  ? "保存修改"
                  : "添加 binding"}
            </button>
          </form>
        </article>
      </div>
    </section>
  );
}
