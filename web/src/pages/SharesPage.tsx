import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";

import { ApiError, listShares } from "../lib/api/client";
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

export function SharesPage() {
  const shares = useQuery({
    queryKey: queryKeys.shares.list(),
    queryFn: listShares,
  });

  const enabled =
    shares.data?.items.filter((share) => share.enabled).length ?? 0;
  const drifted =
    shares.data?.items.filter(
      (share) =>
        share.generation !== share.applied_generation ||
        share.apply_state !== "in_sync",
    ).length ?? 0;

  return (
    <section>
      <div className="page-heading">
        <div>
          <p className="eyebrow">Storage exposure</p>
          <h1>共享</h1>
          <p>
            这里展示 SQLite desired state 与当前 apply generation；创建和修改将继续接 Reconciler Operation。
          </p>
        </div>
        <button
          className="button secondary"
          type="button"
          disabled={shares.isFetching}
          onClick={() => shares.refetch()}
        >
          {shares.isFetching ? "刷新中…" : "刷新"}
        </button>
      </div>

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
