import {
  createBrowserRouter,
  Navigate,
  Outlet,
  useRouteError,
} from "react-router-dom";

import { AppShell } from "./layout/AppShell";
import { useAuth } from "../features/auth/AuthProvider";
import { DashboardPage } from "../pages/DashboardPage";
import { LoginPage } from "../pages/LoginPage";
import { ProfilePage } from "../pages/ProfilePage";
import { SetupPage } from "../pages/SetupPage";

function LoadingScreen() {
  return (
    <main className="center-screen" aria-busy="true">
      <div className="brand-mark" aria-hidden="true">n</div>
      <p>正在连接 naos…</p>
    </main>
  );
}

function ProtectedRoute() {
  const auth = useAuth();

  if (auth.loading || auth.initialized === null) {
    return <LoadingScreen />;
  }

  if (!auth.initialized) {
    return <Navigate to="/setup" replace />;
  }

  if (!auth.authenticated) {
    return <Navigate to="/login" replace />;
  }

  return <Outlet />;
}

function RouteErrorPage() {
  const error = useRouteError();
  const message =
    error instanceof Error ? error.message : "页面加载失败，请返回后重试。";

  return (
    <main className="center-screen">
      <section className="auth-card">
        <p className="eyebrow">Route error</p>
        <h1>页面无法打开</h1>
        <p className="muted">{message}</p>
        <a className="button primary" href="/">返回 Dashboard</a>
      </section>
    </main>
  );
}

export const router = createBrowserRouter([
  {
    path: "/setup",
    element: <SetupPage />,
    errorElement: <RouteErrorPage />,
  },
  {
    path: "/login",
    element: <LoginPage />,
    errorElement: <RouteErrorPage />,
  },
  {
    element: <ProtectedRoute />,
    errorElement: <RouteErrorPage />,
    children: [
      {
        element: <AppShell />,
        children: [
          { index: true, element: <DashboardPage /> },
          { path: "profile", element: <ProfilePage /> },
        ],
      },
    ],
  },
  {
    path: "*",
    element: <Navigate to="/" replace />,
  },
]);
