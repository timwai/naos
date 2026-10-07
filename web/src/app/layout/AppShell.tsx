import { NavLink, Outlet } from "react-router-dom";

import { useAuth } from "../../features/auth/AuthProvider";

function navClass({ isActive }: { isActive: boolean }) {
  return isActive ? "nav-link active" : "nav-link";
}

export function AppShell() {
  const auth = useAuth();
  const isAdmin = auth.user?.role === "admin";

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="sidebar-brand">
          <span className="brand-mark small" aria-hidden="true">n</span>
          <div>
            <strong>naos</strong>
            <span>NAS control plane</span>
          </div>
        </div>

        <nav className="nav-stack" aria-label="主导航">
          <NavLink className={navClass} to="/" end>
            <span>概览</span>
            <small>Dashboard</small>
          </NavLink>
          <NavLink className={navClass} to="/profile">
            <span>个人与会话</span>
            <small>Profile</small>
          </NavLink>
        </nav>

        <div className="sidebar-footer">
          <span className="role-pill">{isAdmin ? "ADMIN" : "USER"}</span>
          <strong>{auth.user?.username}</strong>
          <button
            className="button ghost compact"
            type="button"
            onClick={() => void auth.logout()}
          >
            退出登录
          </button>
        </div>
      </aside>

      <div className="workspace">
        <header className="topbar">
          <div>
            <span className="status-dot" aria-hidden="true" />
            <span>控制面已连接</span>
          </div>
          <span className="muted">localhost-first · secure session</span>
        </header>

        <main className="page-content">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
