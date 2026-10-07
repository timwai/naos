import { Navigate, Outlet, Route, Routes } from "react-router-dom";

import { useSession } from "../features/auth/queries";
import { AppShell } from "./layout/AppShell";
import { DashboardPage } from "../pages/DashboardPage";
import { LoginPage } from "../pages/LoginPage";
import { PlaceholderPage } from "../pages/PlaceholderPage";
import { ProfilePage } from "../pages/ProfilePage";
import { SettingsPage } from "../pages/SettingsPage";

function RequireAuth() {
  const session = useSession();

  if (session.isPending) {
    return <div className="center-state">正在恢复会话…</div>;
  }

  if (session.isError) {
    return (
      <div className="center-state error-text">
        无法连接 naosd，请确认管理服务正在运行。
      </div>
    );
  }

  if (!session.data?.authenticated) {
    return <Navigate to="/login" replace />;
  }

  return <Outlet />;
}

function RequireAdmin() {
  const session = useSession();

  if (session.data?.user?.role !== "admin") {
    return <Navigate to="/files" replace />;
  }

  return <Outlet />;
}

export function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route element={<RequireAuth />}>
        <Route element={<AppShell />}>
          <Route index element={<DashboardPage />} />
          <Route
            path="files"
            element={
              <PlaceholderPage
                title="文件"
                description="文件浏览 API 接线将在下一步落地。"
              />
            }
          />
          <Route path="profile" element={<ProfilePage />} />

          <Route element={<RequireAdmin />}>
            <Route
              path="shares"
              element={
                <PlaceholderPage
                  title="共享"
                  description="共享、ACL 与 NFS binding 将直接使用后端 API。"
                />
              }
            />
            <Route
              path="users"
              element={
                <PlaceholderPage
                  title="用户与组"
                  description="不会使用前端 mock 用户数据。"
                />
              }
            />
            <Route
              path="acl-simulator"
              element={
                <PlaceholderPage
                  title="权限模拟器"
                  description="模拟结果将由后端 acl-engine 返回。"
                />
              }
            />
            <Route
              path="audit"
              element={
                <PlaceholderPage
                  title="审计"
                  description="等待审计后端 API 接入。"
                />
              }
            />
            <Route path="settings" element={<SettingsPage />} />
          </Route>
        </Route>
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
