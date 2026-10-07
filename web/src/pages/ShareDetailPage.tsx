import {
  useMutation,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";
import { useState, type FormEvent } from "react";
import { Link, useParams } from "react-router-dom";

import {
  ApiError,
  createNfsBinding,
  deleteNfsBinding,
  getShare,
  listNfsBindings,
  listShareAcl,
  listUsers,
  updateNfsBinding,
  type NfsBindingDto,
  type NfsBindingUpsertRequest,
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

export function ShareDetailPage() {
  const { id = "" } = useParams();
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

  const selectedUserId =
    userId || users.data?.items.find((user) => user.enabled)?.id || "";

  const resetForm = () => {
    setEditingId(null);
    setCidr("");
    setUid("");
    setUserId("");
    setPermission("ro");
  };

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

      {share.data.comment && (
        <article className="panel detail-comment">{share.data.comment}</article>
      )}

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
