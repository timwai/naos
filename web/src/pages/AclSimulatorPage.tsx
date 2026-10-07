import { useMutation, useQuery } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";

import {
  ApiError,
  listShareAcl,
  listShares,
  listUsers,
  simulateShareAcl,
} from "../lib/api/client";
import { queryKeys } from "../lib/api/queryKeys";

const operations = [
  ["read", "读取"],
  ["write", "写入"],
  ["list", "列目录"],
  ["stat", "读取属性"],
  ["download", "下载"],
  ["create", "创建文件"],
  ["upload", "上传"],
  ["mkdir", "创建目录"],
] as const;

function errorMessage(error: unknown) {
  if (error instanceof ApiError) {
    return error.body?.message ?? error.message;
  }
  if (error instanceof Error) {
    return error.message;
  }
  return "请求失败";
}

export function AclSimulatorPage() {
  const shares = useQuery({
    queryKey: queryKeys.shares.list(),
    queryFn: listShares,
  });
  const users = useQuery({
    queryKey: queryKeys.users.list(),
    queryFn: listUsers,
  });

  const [shareId, setShareId] = useState("");
  const [userId, setUserId] = useState("");
  const [relPath, setRelPath] = useState("/");
  const [operation, setOperation] = useState("read");

  const selectedShareId = shareId || shares.data?.items[0]?.id || "";
  const selectedUserId =
    userId || users.data?.items.find((user) => user.enabled)?.id || "";

  const acl = useQuery({
    queryKey: queryKeys.shares.acl(selectedShareId),
    queryFn: () => listShareAcl(selectedShareId),
    enabled: Boolean(selectedShareId),
  });

  const simulation = useMutation({
    mutationFn: () =>
      simulateShareAcl(selectedShareId, {
        user_id: selectedUserId,
        rel_path: relPath,
        operation,
      }),
  });

  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (!selectedShareId || !selectedUserId) {
      return;
    }
    simulation.mutate();
  };

  const hasInputs = Boolean(selectedShareId && selectedUserId);

  return (
    <section>
      <div className="page-heading">
        <div>
          <p className="eyebrow">Authorization</p>
          <h1>权限模拟器</h1>
          <p>
            最终 allow / deny 与命中规则完全由后端 acl-engine 计算，页面不重算 ACL。
          </p>
        </div>
      </div>

      <div className="acl-layout">
        <article className="panel acl-simulator-card">
          <div className="panel-heading">
            <div>
              <h2>模拟文件操作</h2>
              <p>选择共享、用户、相对路径与操作类型。</p>
            </div>
          </div>

          <form className="acl-form" onSubmit={submit}>
            <label>
              共享
              <select
                value={selectedShareId}
                onChange={(event) => {
                  setShareId(event.target.value);
                  simulation.reset();
                }}
                disabled={shares.isPending || shares.isError}
                required
              >
                {shares.data?.items.length ? null : (
                  <option value="">没有可用共享</option>
                )}
                {shares.data?.items.map((share) => (
                  <option key={share.id} value={share.id}>
                    {share.name}
                  </option>
                ))}
              </select>
            </label>

            <label>
              用户
              <select
                value={selectedUserId}
                onChange={(event) => {
                  setUserId(event.target.value);
                  simulation.reset();
                }}
                disabled={users.isPending || users.isError}
                required
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
              相对路径
              <input
                value={relPath}
                onChange={(event) => {
                  setRelPath(event.target.value);
                  simulation.reset();
                }}
                placeholder="/docs/report.txt"
                required
              />
            </label>

            <label>
              操作
              <select
                value={operation}
                onChange={(event) => {
                  setOperation(event.target.value);
                  simulation.reset();
                }}
              >
                {operations.map(([value, label]) => (
                  <option key={value} value={value}>
                    {label} · {value}
                  </option>
                ))}
              </select>
            </label>

            <button
              type="submit"
              className="button primary"
              disabled={!hasInputs || simulation.isPending}
            >
              {simulation.isPending ? "模拟中…" : "运行模拟"}
            </button>
          </form>

          {(shares.isError || users.isError) && (
            <div className="error-box acl-error">
              {shares.isError
                ? errorMessage(shares.error)
                : errorMessage(users.error)}
            </div>
          )}

          {simulation.isError && (
            <div className="error-box acl-error">
              {errorMessage(simulation.error)}
            </div>
          )}

          {simulation.data && (
            <div
              className={
                simulation.data.allowed
                  ? "acl-result allowed"
                  : "acl-result denied"
              }
            >
              <div className="acl-result-heading">
                <div>
                  <span className="acl-result-label">最终结果</span>
                  <strong>
                    {simulation.data.allowed ? "ALLOW" : "DENY"}
                  </strong>
                </div>
                <span className="permission-pill">
                  {simulation.data.permission}
                </span>
              </div>

              <p>{simulation.data.explanation}</p>
              <div className="acl-result-meta">
                匹配深度：
                {simulation.data.matched_depth === null
                  ? "无"
                  : simulation.data.matched_depth}
              </div>

              {simulation.data.matched_rules.length > 0 && (
                <div className="matched-rule-list">
                  {simulation.data.matched_rules.map((rule, index) => (
                    <article
                      className="matched-rule"
                      key={`${rule.subject}-${rule.rel_path}-${index}`}
                    >
                      <strong>{rule.subject}</strong>
                      <span>{rule.rel_path}</span>
                      <span>{rule.permission}</span>
                      <span>{rule.inherit ? "inherit" : "exact"}</span>
                    </article>
                  ))}
                </div>
              )}
            </div>
          )}
        </article>

        <article className="panel acl-rules-card">
          <div className="panel-heading">
            <div>
              <h2>当前 ACL</h2>
              <p>只读展示当前 share_acl 持久化规则。</p>
            </div>
            {acl.data && <span>{acl.data.items.length} 条</span>}
          </div>

          {!selectedShareId ? (
            <div className="inline-state settings-state">请先选择共享。</div>
          ) : acl.isPending ? (
            <div className="inline-state settings-state">正在加载 ACL…</div>
          ) : acl.isError ? (
            <div className="error-box settings-error">
              {errorMessage(acl.error)}
            </div>
          ) : acl.data.items.length === 0 ? (
            <div className="inline-state settings-state">
              当前共享没有 ACL 规则，acl-engine 将默认拒绝。
            </div>
          ) : (
            <div className="acl-rule-list">
              {acl.data.items.map((rule) => (
                <article className="acl-rule-row" key={rule.id}>
                  <div>
                    <strong>
                      {rule.subject.name || rule.subject.id}
                    </strong>
                    <span>
                      {rule.subject.type}:{rule.subject.id}
                    </span>
                  </div>
                  <span className="acl-path">{rule.rel_path}</span>
                  <span className="permission-pill">{rule.permission}</span>
                  <span className="role-pill">
                    {rule.inherit ? "inherit" : "exact"}
                  </span>
                </article>
              ))}
            </div>
          )}
        </article>
      </div>
    </section>
  );
}
