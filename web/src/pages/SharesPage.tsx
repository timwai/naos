import { useOperation } from "../features/operations/useOperation";
import {
  useMutation,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";
import { useEffect, useState, type FormEvent } from "react";
import { Link, useNavigate } from "react-router-dom";

import {
  ApiError,
  createShare,
  listShares,
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

function protocolLabels(share: {
  smb_enabled: boolean;
  webdav_enabled: boolean;
  nfs_enabled: boolean;
}) {
  const items = [];
  if (share.smb_enabled) items.push("SMB");
  if (share.webdav_enabled) items.push("WebDAV");
  if (share.nfs_enabled) items.push("NFS");
  return items;
}

function isTerminal(state: string | undefined) {
  return state === "succeeded" || state === "failed" || state === "degraded";
}

const emptyDraft: ShareWriteRequest = {
  name: "",
  path: "",
  comment: null,
  enabled: true,
  smb_enabled: true,
  webdav_enabled: false,
  nfs_enabled: false,
};

export function SharesPage() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [showCreate, setShowCreate] = useState(false);
  const [draft, setDraft] = useState<ShareWriteRequest>(emptyDraft);
  const [operationId, setOperationId] = useState<string | null>(null);

  const shares = useQuery({
    queryKey: queryKeys.shares.list(),
    queryFn: listShares,
  });

  const create = useMutation({
    mutationFn: (input: ShareWriteRequest) => createShare(input),
    onSuccess: (operation) => setOperationId(operation.operation_id),
  });

  const operation = useOperation(operationId);

  useEffect(() => {
    if (operation.data?.state !== "succeeded") {
      return;
    }
    void queryClient.invalidateQueries({
      queryKey: queryKeys.shares.list(),
    });
    const shareId = operation.data.resource_id;
    setOperationId(null);
    setDraft(emptyDraft);
    setShowCreate(false);
    if (shareId) {
      navigate(`/shares/${shareId}`);
    }
  }, [navigate, operation.data, queryClient]);

  const enabled =
    shares.data?.items.filter((share) => share.enabled).length ?? 0;
  const drifted =
    shares.data?.items.filter(
      (share) =>
        share.generation !== share.applied_generation ||
        share.apply_state !== "in_sync",
    ).length ?? 0;

  const submit = (event: FormEvent) => {
    event.preventDefault();
    setOperationId(null);
    create.mutate({
      ...draft,
      name: draft.name.trim(),
      path: draft.path.trim(),
      comment: draft.comment?.trim() || null,
    });
  };

  return (
    <section>
      <div className="page-heading">
        <div>
          <p className="eyebrow">Storage exposure</p>
          <h1>共享</h1>
          <p>
            SQLite 保存 desired state；创建、修改和删除都通过 Operation +
            Reconciler 异步落地。
          </p>
        </div>
        <div className="heading-actions">
          <button
            className="button secondary"
            type="button"
            disabled={shares.isFetching}
            onClick={() => shares.refetch()}
          >
            {shares.isFetching ? "刷新中…" : "刷新"}
          </button>
          <button
            className="button primary"
            type="button"
            onClick={() => {
              setShowCreate((value) => !value);
              create.reset();
              setOperationId(null);
            }}
          >
            {showCreate ? "取消创建" : "创建共享"}
          </button>
        </div>
      </div>

      {showCreate && (
        <article className="panel share-create-panel">
          <div className="panel-heading">
            <div>
              <h2>创建共享</h2>
              <p>
                路径必须是宿主机上已经存在的绝对目录；后端会 canonicalize 后再写 desired state。
              </p>
            </div>
          </div>

          <form className="share-config-form" onSubmit={submit}>
            <label>
              名称
              <input
                value={draft.name}
                onChange={(event) =>
                  setDraft((value) => ({
                    ...value,
                    name: event.target.value,
                  }))
                }
                placeholder="media"
                required
              />
            </label>
            <label>
              宿主路径
              <input
                value={draft.path}
                onChange={(event) =>
                  setDraft((value) => ({
                    ...value,
                    path: event.target.value,
                  }))
                }
                placeholder="/data/media"
                required
              />
            </label>
            <label className="share-config-comment">
              说明
              <input
                value={draft.comment ?? ""}
                onChange={(event) =>
                  setDraft((value) => ({
                    ...value,
                    comment: event.target.value,
                  }))
                }
                placeholder="家庭影音多媒体共享库"
              />
            </label>

            <div className="share-toggle-grid">
              <label className="toggle-field">
                <input
                  type="checkbox"
                  checked={draft.enabled}
                  onChange={(event) =>
                    setDraft((value) => ({
                      ...value,
                      enabled: event.target.checked,
                    }))
                  }
                />
                <span>启用共享</span>
              </label>
              <label className="toggle-field">
                <input
                  type="checkbox"
                  checked={draft.smb_enabled}
                  onChange={(event) =>
                    setDraft((value) => ({
                      ...value,
                      smb_enabled: event.target.checked,
                    }))
                  }
                />
                <span>SMB</span>
              </label>
              <label className="toggle-field">
                <input
                  type="checkbox"
                  checked={draft.webdav_enabled}
                  onChange={(event) =>
                    setDraft((value) => ({
                      ...value,
                      webdav_enabled: event.target.checked,
                    }))
                  }
                />
                <span>WebDAV</span>
              </label>
              <label className="toggle-field">
                <input
                  type="checkbox"
                  checked={draft.nfs_enabled}
                  onChange={(event) =>
                    setDraft((value) => ({
                      ...value,
                      nfs_enabled: event.target.checked,
                    }))
                  }
                />
                <span>NFS</span>
              </label>
            </div>

            {create.isError && (
              <div className="error-box">{errorMessage(create.error)}</div>
            )}
            {operation.isError && (
              <div className="error-box">{errorMessage(operation.error)}</div>
            )}
            {operation.data && (
              <div className="share-operation-state">
                <div>
                  <strong>{operation.data.state}</strong>
                  <span>{operation.data.phase ?? "queued"}</span>
                </div>
                <span>{operation.data.progress}%</span>
              </div>
            )}
            {operation.data &&
              (operation.data.state === "failed" ||
                operation.data.state === "degraded") && (
                <div className="error-box">
                  {operation.data.error_code ?? "SHARE_APPLY_FAILED"}
                </div>
              )}

            <button
              className="button primary"
              type="submit"
              disabled={
                create.isPending ||
                (Boolean(operationId) &&
                  !isTerminal(operation.data?.state))
              }
            >
              {create.isPending ? "提交中…" : "创建并 Apply"}
            </button>
          </form>
        </article>
      )}

      <div className="metric-grid user-metrics">
        <article className="metric-card">
          <span>共享总数</span>
          <strong>{shares.data?.items.length ?? "—"}</strong>
          <small>desired shares</small>
        </article>
        <article className="metric-card">
          <span>已启用</span>
          <strong>{shares.data ? enabled : "—"}</strong>
          <small>enabled shares</small>
        </article>
        <article className="metric-card">
          <span>待同步 / degraded</span>
          <strong>{shares.data ? drifted : "—"}</strong>
          <small>generation / apply state</small>
        </article>
      </div>

      <article className="panel">
        <div className="panel-heading">
          <div>
            <h2>共享目录</h2>
            <p>宿主路径只在管理员页面展示；协议状态来自后端持久化配置。</p>
          </div>
        </div>

        {shares.isPending ? (
          <div className="inline-state settings-state">正在加载共享…</div>
        ) : shares.isError ? (
          <div className="error-box settings-error">
            {errorMessage(shares.error)}
          </div>
        ) : shares.data.items.length === 0 ? (
          <div className="inline-state settings-state">尚未创建共享。</div>
        ) : (
          <div className="share-list">
            {shares.data.items.map((share) => {
              const protocols = protocolLabels(share);
              return (
                <article className="share-row" key={share.id}>
                  <div className="share-main">
                    <div className="share-title">
                      <strong>{share.name}</strong>
                      <span
                        className={
                          share.enabled
                            ? "status-pill enabled"
                            : "status-pill disabled"
                        }
                      >
                        {share.enabled ? "enabled" : "disabled"}
                      </span>
                      <span className={"apply-pill " + share.apply_state}>
                        {share.apply_state}
                      </span>
                    </div>
                    <span className="share-path">{share.path}</span>
                    {share.comment && (
                      <span className="share-comment">{share.comment}</span>
                    )}
                  </div>

                  <div className="share-side">
                    <div className="protocol-pills">
                      {protocols.length ? (
                        protocols.map((protocol) => (
                          <span className="role-pill" key={protocol}>
                            {protocol}
                          </span>
                        ))
                      ) : (
                        <span className="role-pill">no protocol</span>
                      )}
                    </div>
                    <span className="share-generation">
                      gen {share.applied_generation}/{share.generation}
                    </span>
                    <Link
                      className="button secondary button-link"
                      to={`/shares/${share.id}`}
                    >
                      详情
                    </Link>
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
