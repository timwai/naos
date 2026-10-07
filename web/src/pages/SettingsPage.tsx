import {
  useMutation,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";
import { useState, type FormEvent } from "react";

import {
  ApiError,
  createNfsPrincipal,
  deleteNfsPrincipal,
  getOperation,
  getSmbDoctor,
  listNfsPrincipals,
  startSystemVerify,
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

export function SettingsPage() {
  const queryClient = useQueryClient();
  const [principal, setPrincipal] = useState("");
  const [userId, setUserId] = useState("");
  const [verifyOperationId, setVerifyOperationId] = useState<string | null>(
    null,
  );

  const doctor = useQuery({
    queryKey: queryKeys.system.smbDoctor(),
    queryFn: getSmbDoctor,
    staleTime: 15_000,
  });

  const principals = useQuery({
    queryKey: queryKeys.nfs.principals(),
    queryFn: listNfsPrincipals,
  });

  const verify = useMutation({
    mutationFn: startSystemVerify,
    onSuccess: (operation) => {
      setVerifyOperationId(operation.operation_id);
    },
  });

  const verifyOperation = useQuery({
    queryKey: queryKeys.operations.detail(verifyOperationId ?? ""),
    queryFn: () => getOperation(verifyOperationId ?? ""),
    enabled: Boolean(verifyOperationId),
    refetchInterval: (query) =>
      isTerminal(query.state.data?.state) ? false : 1_000,
  });

  const createPrincipal = useMutation({
    mutationFn: createNfsPrincipal,
    onSuccess: async () => {
      setPrincipal("");
      setUserId("");
      await queryClient.invalidateQueries({
        queryKey: queryKeys.nfs.principals(),
      });
    },
  });

  const removePrincipal = useMutation({
    mutationFn: deleteNfsPrincipal,
    onSuccess: async () => {
      await queryClient.invalidateQueries({
        queryKey: queryKeys.nfs.principals(),
      });
    },
  });

  const submitPrincipal = (event: FormEvent) => {
    event.preventDefault();
    createPrincipal.mutate({
      principal: principal.trim(),
      user_id: userId.trim(),
    });
  };

  const providerLabel = doctor.data
    ? `${doctor.data.provider} / ${doctor.data.status}`
    : doctor.isPending
      ? "检查中…"
      : "不可用";

  return (
    <section>
      <div className="page-heading settings-heading">
        <div>
          <p className="eyebrow">System</p>
          <h1>设置与诊断</h1>
          <p>
            系统检查、SMB provider ownership 和 NFS Kerberos 映射均来自 naosd。
          </p>
        </div>
        <button
          className="button primary"
          type="button"
          disabled={
            verify.isPending ||
            (Boolean(verifyOperationId) &&
              !isTerminal(verifyOperation.data?.state))
          }
          onClick={() => verify.mutate()}
        >
          {verify.isPending ? "正在创建检查…" : "运行 Verify"}
        </button>
      </div>

      {verify.isError && (
        <div className="error-box">{errorMessage(verify.error)}</div>
      )}

      {verifyOperationId && (
        <article className="panel operation-panel">
          <div className="panel-heading">
            <div>
              <h2>System Verify</h2>
              <p className="mono-copy">{verifyOperationId}</p>
            </div>
            <span className="role-pill">
              {verifyOperation.data?.state ?? "starting"}
            </span>
          </div>

          {verifyOperation.isError ? (
            <div className="error-box">
              {errorMessage(verifyOperation.error)}
            </div>
          ) : (
            <>
              <div className="progress-track" aria-label="Verify progress">
                <span
                  style={{
                    width: `${verifyOperation.data?.progress ?? 0}%`,
                  }}
                />
              </div>
              <div className="operation-meta">
                <span>
                  {verifyOperation.data?.progress ?? 0}% ·{" "}
                  {verifyOperation.data?.phase ?? "等待执行"}
                </span>
                {verifyOperation.data?.error_code && (
                  <span className="error-text">
                    {verifyOperation.data.error_code}
                  </span>
                )}
              </div>
            </>
          )}
        </article>
      )}

      <div className="settings-grid">
        <article className="panel settings-card">
          <div className="panel-heading">
            <div>
              <h2>SMB Doctor</h2>
              <p>检查 system provider 与 TCP/445 ownership。</p>
            </div>
            <button
              className="button secondary"
              type="button"
              disabled={doctor.isFetching}
              onClick={() => doctor.refetch()}
            >
              {doctor.isFetching ? "刷新中…" : "刷新"}
            </button>
          </div>

          {doctor.isError ? (
            <div className="error-box">{errorMessage(doctor.error)}</div>
          ) : (
            <>
              <dl className="settings-facts">
                <div>
                  <dt>Provider</dt>
                  <dd>{providerLabel}</dd>
                </div>
                <div>
                  <dt>Service</dt>
                  <dd>{doctor.data?.service_name ?? "—"}</dd>
                </div>
                <div>
                  <dt>Installed / Running</dt>
                  <dd>
                    {doctor.data
                      ? `${doctor.data.installed ? "yes" : "no"} / ${doctor.data.running ? "yes" : "no"}`
                      : "—"}
                  </dd>
                </div>
                <div>
                  <dt>TCP/445</dt>
                  <dd>
                    {doctor.data?.listener_445
                      ? doctor.data.listener_445.process ??
                        doctor.data.listener_445.local_address
                      : "未检测到 listener"}
                  </dd>
                </div>
                <div>
                  <dt>Config mode</dt>
                  <dd>{doctor.data?.config_mode ?? "—"}</dd>
                </div>
                <div>
                  <dt>Managed by naos</dt>
                  <dd>{doctor.data?.managed_by_naos ? "yes" : "no"}</dd>
                </div>
              </dl>

              {doctor.data?.findings.length ? (
                <div className="finding-list compact-findings">
                  {doctor.data.findings.map((finding) => (
                    <article className="finding" key={finding.code}>
                      <div>
                        <strong>{finding.summary}</strong>
                        <p>{finding.detail}</p>
                        <small>{finding.remediation}</small>
                      </div>
                      <span className={"severity " + finding.severity}>
                        {finding.severity}
                      </span>
                    </article>
                  ))}
                </div>
              ) : (
                <div className="success-box settings-success">
                  当前没有 Doctor finding。
                </div>
              )}
            </>
          )}
        </article>

        <article className="panel settings-card">
          <div className="panel-heading">
            <div>
              <h2>NFS Kerberos principals</h2>
              <p>
                将完整 Kerberos principal 精确映射到已启用的 naos user ID。
              </p>
            </div>
          </div>

          <form className="principal-form" onSubmit={submitPrincipal}>
            <label>
              Principal
              <input
                placeholder="alice@EXAMPLE.COM"
                value={principal}
                onChange={(event) => setPrincipal(event.target.value)}
                required
              />
            </label>
            <label>
              User ID
              <input
                placeholder="usr_..."
                value={userId}
                onChange={(event) => setUserId(event.target.value)}
                required
              />
            </label>
            <button
              className="button primary"
              type="submit"
              disabled={createPrincipal.isPending}
            >
              {createPrincipal.isPending ? "绑定中…" : "添加映射"}
            </button>
          </form>

          {createPrincipal.isError && (
            <div className="error-box settings-error">
              {errorMessage(createPrincipal.error)}
            </div>
          )}

          {principals.isPending ? (
            <div className="inline-state settings-state">
              正在加载 principal 映射…
            </div>
          ) : principals.isError ? (
            <div className="error-box settings-error">
              {errorMessage(principals.error)}
            </div>
          ) : principals.data.items.length === 0 ? (
            <div className="inline-state settings-state">
              尚未配置 Kerberos principal。
            </div>
          ) : (
            <div className="principal-list">
              {principals.data.items.map((item) => (
                <article className="principal-row" key={item.id}>
                  <div>
                    <strong>{item.principal}</strong>
                    <span>{item.user_id}</span>
                  </div>
                  <button
                    className="button danger"
                    type="button"
                    disabled={removePrincipal.isPending}
                    onClick={() => removePrincipal.mutate(item.id)}
                  >
                    删除
                  </button>
                </article>
              ))}
            </div>
          )}

          {removePrincipal.isError && (
            <div className="error-box settings-error">
              {errorMessage(removePrincipal.error)}
            </div>
          )}
        </article>
      </div>
    </section>
  );
}
