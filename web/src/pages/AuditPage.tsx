import { useMutation, useQuery } from "@tanstack/react-query";
import { useEffect, useMemo, useState, type FormEvent } from "react";
import { useSearchParams } from "react-router-dom";

import {
  ApiError,
  exportAudit,
  listAudit,
  type AuditFilters,
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

function positivePage(value: string | null) {
  const parsed = Number.parseInt(value ?? "1", 10);
  return Number.isSafeInteger(parsed) && parsed > 0 ? parsed : 1;
}

function eventTitle(item: {
  actor: { name?: string | null; id?: string | null; type: string };
  action: string;
}) {
  return item.actor.name || item.actor.id || item.actor.type || item.action;
}

export function AuditPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const protocol = searchParams.get("protocol") ?? "";
  const result = searchParams.get("result") ?? "";
  const userId = searchParams.get("user_id") ?? "";
  const shareId = searchParams.get("share_id") ?? "";
  const q = searchParams.get("q") ?? "";
  const page = positivePage(searchParams.get("page"));

  const [protocolDraft, setProtocolDraft] = useState(protocol);
  const [resultDraft, setResultDraft] = useState(result);
  const [userDraft, setUserDraft] = useState(userId);
  const [shareDraft, setShareDraft] = useState(shareId);
  const [qDraft, setQDraft] = useState(q);

  const [exportNotice, setExportNotice] = useState<string | null>(null);

  useEffect(() => setProtocolDraft(protocol), [protocol]);
  useEffect(() => setResultDraft(result), [result]);
  useEffect(() => setUserDraft(userId), [userId]);
  useEffect(() => setShareDraft(shareId), [shareId]);
  useEffect(() => setQDraft(q), [q]);

  const filters = useMemo<AuditFilters>(
    () => ({
      protocol: protocol || undefined,
      result: result || undefined,
      user_id: userId || undefined,
      share_id: shareId || undefined,
      q: q || undefined,
      page,
      page_size: 50,
    }),
    [page, protocol, q, result, shareId, userId],
  );

  const audit = useQuery({
    queryKey: queryKeys.audit.list(filters),
    queryFn: () => listAudit(filters),
  });

  const exportCsv = useMutation({
    mutationFn: () => exportAudit(filters),
    onSuccess: ({ blob, total, exported }) => {
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = "naos-audit.csv";
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      URL.revokeObjectURL(url);

      setExportNotice(
        total > exported
          ? `已导出前 ${exported} / ${total} 条；缩小筛选范围可导出完整结果。`
          : `已导出 ${exported} 条审计记录。`,
      );
    },
  });

  const totalPages = audit.data
    ? Math.max(1, Math.ceil(audit.data.total / audit.data.page_size))
    : 1;

  const applyFilters = (event: FormEvent) => {
    event.preventDefault();
    setExportNotice(null);
    const next = new URLSearchParams();
    if (protocolDraft) next.set("protocol", protocolDraft);
    if (resultDraft) next.set("result", resultDraft);
    if (userDraft.trim()) next.set("user_id", userDraft.trim());
    if (shareDraft.trim()) next.set("share_id", shareDraft.trim());
    if (qDraft.trim()) next.set("q", qDraft.trim());
    next.set("page", "1");
    setSearchParams(next);
  };

  const changePage = (nextPage: number) => {
    const next = new URLSearchParams(searchParams);
    next.set("page", String(nextPage));
    setSearchParams(next);
  };

  const clearFilters = () => {
    setExportNotice(null);
    setSearchParams({ page: "1" });
  };

  return (
    <section>
      <div className="page-heading">
        <div>
          <p className="eyebrow">Observability</p>
          <h1>审计</h1>
          <p>
            登录、管理操作与协议事件统一从 audit_log 查询；筛选和分页都由后端执行。
          </p>
        </div>
        <div className="heading-actions">
          <button
            className="button secondary"
            type="button"
            disabled={
              exportCsv.isPending ||
              audit.isPending ||
              audit.isError ||
              audit.data?.total === 0
            }
            onClick={() => {
              setExportNotice(null);
              exportCsv.mutate();
            }}
          >
            {exportCsv.isPending ? "导出中…" : "导出 CSV"}
          </button>
          <button
            className="button secondary"
            type="button"
            disabled={audit.isFetching}
            onClick={() => audit.refetch()}
          >
            {audit.isFetching ? "刷新中…" : "刷新"}
          </button>
        </div>
      </div>

      <article className="panel audit-filter-panel">
        <form className="audit-filter-form" onSubmit={applyFilters}>
          <label>
            Protocol
            <select
              value={protocolDraft}
              onChange={(event) => setProtocolDraft(event.target.value)}
            >
              <option value="">全部</option>
              <option value="smb">SMB</option>
              <option value="webdav">WebDAV</option>
              <option value="nfs">NFS</option>
            </select>
          </label>

          <label>
            Result
            <select
              value={resultDraft}
              onChange={(event) => setResultDraft(event.target.value)}
            >
              <option value="">全部</option>
              <option value="allow">allow</option>
              <option value="deny">deny</option>
              <option value="error">error</option>
            </select>
          </label>

          <label>
            User ID
            <input
              value={userDraft}
              onChange={(event) => setUserDraft(event.target.value)}
              placeholder="usr_..."
            />
          </label>

          <label>
            Share ID
            <input
              value={shareDraft}
              onChange={(event) => setShareDraft(event.target.value)}
              placeholder="shr_..."
            />
          </label>

          <label className="audit-search-field">
            关键词
            <input
              value={qDraft}
              onChange={(event) => setQDraft(event.target.value)}
              placeholder="动作、路径、用户、IP 或 detail"
            />
          </label>

          <div className="audit-filter-actions">
            <button className="button primary" type="submit">
              应用筛选
            </button>
            <button
              className="button secondary"
              type="button"
              onClick={clearFilters}
            >
              清空
            </button>
          </div>
        </form>
      </article>

      {exportNotice && <div className="success-box">{exportNotice}</div>}
      {exportCsv.isError && (
        <div className="error-box settings-error">
          {errorMessage(exportCsv.error)}
        </div>
      )}

      <article className="panel audit-panel">
        <div className="panel-heading">
          <div>
            <h2>事件</h2>
            <p>
              {audit.data
                ? `共 ${audit.data.total} 条 · 第 ${audit.data.page}/${totalPages} 页`
                : "正在读取审计日志"}
            </p>
          </div>
        </div>

        {audit.isPending ? (
          <div className="inline-state settings-state">正在加载审计记录…</div>
        ) : audit.isError ? (
          <div className="error-box settings-error">
            {errorMessage(audit.error)}
          </div>
        ) : audit.data.items.length === 0 ? (
          <div className="inline-state settings-state">
            当前筛选条件下没有审计记录。
          </div>
        ) : (
          <div className="audit-list">
            {audit.data.items.map((item) => (
              <article className="audit-row" key={item.id}>
                <div className="audit-primary">
                  <div className="audit-title">
                    <strong>{item.action}</strong>
                    <span
                      className={
                        item.result === "allow"
                          ? "status-pill enabled"
                          : "status-pill audit-deny"
                      }
                    >
                      {item.result}
                    </span>
                    {item.protocol && (
                      <span className="role-pill">
                        {item.protocol.toUpperCase()}
                      </span>
                    )}
                  </div>
                  <span>
                    {eventTitle(item)} ·{" "}
                    {new Date(item.timestamp).toLocaleString()}
                  </span>
                  {(item.path || item.client_ip) && (
                    <span className="audit-context">
                      {[item.path, item.client_ip].filter(Boolean).join(" · ")}
                    </span>
                  )}
                </div>

                <div className="audit-meta">
                  {item.share_id && <span>{item.share_id}</span>}
                  {item.operation_id && <span>{item.operation_id}</span>}
                  {item.detail !== null && item.detail !== undefined && (
                    <details>
                      <summary>detail</summary>
                      <pre>{JSON.stringify(item.detail, null, 2)}</pre>
                    </details>
                  )}
                </div>
              </article>
            ))}
          </div>
        )}

        {audit.data && audit.data.total > audit.data.page_size && (
          <div className="audit-pagination">
            <button
              className="button secondary"
              type="button"
              disabled={page <= 1}
              onClick={() => changePage(page - 1)}
            >
              上一页
            </button>
            <span>
              {page} / {totalPages}
            </span>
            <button
              className="button secondary"
              type="button"
              disabled={page >= totalPages}
              onClick={() => changePage(page + 1)}
            >
              下一页
            </button>
          </div>
        )}
      </article>
    </section>
  );
}
