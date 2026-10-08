import { useMutation, useQueryClient } from "@tanstack/react-query";
import { NavLink, Outlet, useNavigate } from "react-router-dom";

import { useSession } from "../../features/auth/queries";
import { logout } from "../../lib/api/client";
import { queryKeys } from "../../lib/api/queryKeys";

const adminNav = [
  ["/", "Dashboard"],
  ["/files", "文件"],
  ["/shares", "共享"],
  ["/users", "用户与组"],
  ["/acl-simulator", "权限模拟器"],
  ["/audit", "审计"],
  ["/settings", "设置"],
] as const;

export function AppShell() {
  const session = useSession();
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const isAdmin = session.data?.user?.role === "admin";

  const logoutMutation = useMutation({
    mutationFn: logout,
    onSuccess: async () => {
      await queryClient.cancelQueries();
      queryClient.clear();
      queryClient.setQueryData(queryKeys.auth.session(), {
        authenticated: false,
        user: null,
        csrf_token: null,
      });
      navigate("/login", { replace: true });
    },
  });

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <span className="brand-mark">N</span>
          <span>
            <strong>naos</strong>
            <small>NAS control plane</small>
          </span>
        </div>

        <nav className="nav-list" aria-label="主导航">
          {(isAdmin ? adminNav : adminNav.slice(0, 2)).map(([to, label]) => (
            <NavLink
              key={to}
              to={to}
              end={to === "/"}
              className={({ isActive }) =>
                isActive ? "nav-link active" : "nav-link"
              }
            >
              {label}
            </NavLink>
          ))}
        </nav>

        <NavLink className="nav-link profile-link" to="/profile">
          个人安全
        </NavLink>
      </aside>

      <main className="main-panel">
        <header className="topbar">
          <div>
            <strong>{session.data?.user?.username}</strong>
            <span className="role-pill">{session.data?.user?.role}</span>
          </div>
          <button
            className="button secondary"
            type="button"
            disabled={logoutMutation.isPending}
            onClick={() => logoutMutation.mutate()}
          >
            {logoutMutation.isPending ? "退出中…" : "退出登录"}
          </button>
        </header>
        <div className="page-container">
          {logoutMutation.isError && (
            <div className="error-box" role="alert">
              退出登录失败，请重试。
            </div>
          )}
          <Outlet />
        </div>
      </main>
    </div>
  );
}
