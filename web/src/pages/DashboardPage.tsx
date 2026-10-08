import { useQuery } from "@tanstack/react-query";

import { useSession } from "../features/auth/queries";
import { getReadiness, getSmbDoctor } from "../lib/api/client";
import { queryKeys } from "../lib/api/queryKeys";

export function DashboardPage() {
  const session = useSession();
  const readiness = useQuery({
    queryKey: queryKeys.health.ready(),
    queryFn: getReadiness,
    refetchInterval: 30_000,
  });
  const doctor = useQuery({
    queryKey: queryKeys.system.smbDoctor(),
    queryFn: getSmbDoctor,
    enabled: session.data?.user?.role === "admin",
    staleTime: 30_000,
  });

  const status = readiness.data?.status ?? (readiness.isError ? "error" : "checking");
  const isAdmin = session.data?.user?.role === "admin";
  const provider = doctor.data?.provider ?? "—";
  const doctorStatus = doctor.isError ? "检查失败" : doctor.isPending ? "检查中…" : provider;
  const listener = doctor.data?.listener_445?.process
    ?? doctor.data?.listener_445?.local_address
    ?? "未检测到";

  return (
    <section>
      <div className="page-heading">
        <div>
          <p className="eyebrow">Overview</p>
          <h1>Dashboard</h1>
          <p>这里只展示来自 naosd 的实时状态，不使用前端模拟数据。</p>
        </div>
      </div>

      <div className="metric-grid">
        <article className="metric-card">
          <span>控制面 readiness</span>
          <strong>{status}</strong>
          <small>/health/ready</small>
        </article>

        {isAdmin && (
          <article className="metric-card">
          <span>SMB provider</span>
          <strong>{doctorStatus}</strong>
          <small>{doctor.data?.status ?? "system provider"}</small>
        </article>
        )}

        {isAdmin && (
          <article className="metric-card">
            <span>TCP/445</span>
            <strong>{doctor.isError ? "检查失败" : doctor.isPending ? "检查中…" : listener}</strong>
            <small>
              {doctor.data?.managed_by_naos ? "naos-managed scope" : "provider ownership"}
            </small>
          </article>
        )}
      </div>

      {isAdmin && doctor.isError && (
        <div className="error-box" role="alert">SMB Doctor 检查失败，请在设置与诊断页面重试。</div>
      )}

      {isAdmin && doctor.data?.findings.length ? (
        <div className="panel">
          <div className="panel-heading">
            <h2>SMB Doctor</h2>
            <span>{doctor.data.findings.length} 项</span>
          </div>
          <div className="finding-list">
            {doctor.data.findings.map((finding) => (
              <article key={finding.code} className="finding">
                <div>
                  <strong>{finding.summary}</strong>
                  <p>{finding.detail}</p>
                </div>
                <span className={"severity " + finding.severity}>
                  {finding.severity}
                </span>
              </article>
            ))}
          </div>
        </div>
      ) : null}
    </section>
  );
}
