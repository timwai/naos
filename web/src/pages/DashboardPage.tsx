import { useMutation, useQuery } from "@tanstack/react-query";
import { useState } from "react";

import { useAuth } from "../features/auth/AuthProvider";
import { api, ApiClientError } from "../lib/api/client";
import { queryKeys } from "../lib/api/queryKeys";

function StateBadge({ ok, children }: { ok: boolean; children: string }) {
  return <span className={ok ? "badge success" : "badge warning"}>{children}</span>;
}

export function DashboardPage() {
  const auth = useAuth();
  const isAdmin = auth.user?.role === "admin";
  const [verifyMessage, setVerifyMessage] = useState<string | null>(null);

  const health = useQuery({
    queryKey: queryKeys.health.ready,
    queryFn: api.healthReady,
    refetchInterval: 30_000,
  });

  const doctor = useQuery({
    queryKey: queryKeys.system.smbDoctor,
    queryFn: api.smbDoctor,
    enabled: isAdmin,
    staleTime: 30_000,
  });

  const verify = useMutation({
    mutationFn: api.systemVerify,
    onSuccess: (operation) => {
      setVerifyMessage(`Verify 已排队：${operation.operation_id}`);
    },
    onError: (cause) => {
      setVerifyMessage(
        cause instanceof ApiClientError ? cause.message : "无法启动 Verify。",
      );
    },
  });

  return (
    <div className="page-stack">
      <section className="page-heading">
        <div>
          <p className="eyebrow">Overview</p>
          <h1>系统概览</h1>
          <p className="muted">
            这里只展示服务端真实状态；尚未实现 API 的业务模块不会使用前端 mock。
          </p>
        </div>
        {isAdmin ? (
          <button
            className="button secondary"
            disabled={verify.isPending}
            type="button"
            onClick={() => {
              setVerifyMessage(null);
              verify.mutate();
            }}
          >
            {verify.isPending ? "启动中…" : "运行 System Verify"}
          </button>
        ) : null}
      </section>

      {verifyMessage ? <div className="notice">{verifyMessage}</div> : null}

      <section className="metric-grid">
        <article className="metric-card">
          <span className="metric-label">Control plane</span>
          <strong>{health.data?.status ?? (health.isPending ? "…" : "unavailable")}</strong>
          <StateBadge ok={health.isSuccess}>
            {health.isSuccess ? "READY" : "CHECK"}
          </StateBadge>
        </article>

        <article className="metric-card">
          <span className="metric-label">Session</span>
          <strong>{auth.user?.username ?? "unknown"}</strong>
          <StateBadge ok={auth.authenticated}>
            {auth.authenticated ? "AUTHENTICATED" : "INVALID"}
          </StateBadge>
        </article>

        <article className="metric-card">
          <span className="metric-label">Role</span>
          <strong>{auth.user?.role ?? "unknown"}</strong>
          <span className="badge neutral">
            {auth.user?.enabled === false ? "DISABLED" : "ENABLED"}
          </span>
        </article>
      </section>

      {isAdmin ? (
        <section className="panel">
          <div className="panel-heading">
            <div>
              <p className="eyebrow">SMB provider</p>
              <h2>445 / Provider Doctor</h2>
            </div>
            <button
              className="button ghost compact"
              type="button"
              onClick={() => void doctor.refetch()}
            >
              刷新
            </button>
          </div>

          {doctor.isPending ? <p className="muted">正在检查系统 SMB provider…</p> : null}
          {doctor.isError ? (
            <div className="inline-error">
              {doctor.error instanceof Error ? doctor.error.message : "Doctor 检查失败"}
            </div>
          ) : null}

          {doctor.data ? (
            <>
              <div className="doctor-grid">
                <div>
                  <span>Platform</span>
                  <strong>{doctor.data.platform}</strong>
                </div>
                <div>
                  <span>Provider</span>
                  <strong>{doctor.data.provider}</strong>
                </div>
                <div>
                  <span>Status</span>
                  <strong>{doctor.data.status}</strong>
                </div>
                <div>
                  <span>TCP/445</span>
                  <strong>
                    {doctor.data.listener_445?.local_address ?? "未监听 / 未发现"}
                  </strong>
                </div>
              </div>

              <div className="finding-list">
                {doctor.data.findings.length === 0 ? (
                  <div className="empty-state">没有 Doctor finding。</div>
                ) : (
                  doctor.data.findings.map((finding) => (
                    <article className="finding" key={finding.code}>
                      <div>
                        <span className="badge neutral">{finding.severity}</span>
                        <strong>{finding.summary}</strong>
                      </div>
                      <p>{finding.detail}</p>
                      <small>{finding.remediation}</small>
                    </article>
                  ))
                )}
              </div>
            </>
          ) : null}
        </section>
      ) : null}
    </div>
  );
}
