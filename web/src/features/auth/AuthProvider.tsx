import { useQuery, useQueryClient } from "@tanstack/react-query";
import {
  createContext,
  type ReactNode,
  useCallback,
  useContext,
  useEffect,
  useMemo,
} from "react";

import {
  api,
  type LoginRequest,
  setCsrfToken,
  type SetupAdminRequest,
  type UserDto,
} from "../../lib/api/client";
import { queryKeys } from "../../lib/api/queryKeys";

interface AuthContextValue {
  initialized: boolean | null;
  authenticated: boolean;
  user: UserDto | null;
  loading: boolean;
  login: (input: LoginRequest) => Promise<void>;
  setupAdmin: (input: SetupAdminRequest) => Promise<void>;
  logout: () => Promise<void>;
  refreshSession: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const queryClient = useQueryClient();

  const setupQuery = useQuery({
    queryKey: queryKeys.setup,
    queryFn: api.setupStatus,
  });

  const initialized = setupQuery.data?.initialized ?? null;

  const sessionQuery = useQuery({
    queryKey: queryKeys.auth.session,
    queryFn: api.session,
    enabled: initialized === true,
  });

  useEffect(() => {
    setCsrfToken(sessionQuery.data?.csrf_token);
  }, [sessionQuery.data?.csrf_token]);

  const refreshSession = useCallback(async () => {
    await queryClient.invalidateQueries({ queryKey: queryKeys.auth.session });
  }, [queryClient]);

  const login = useCallback(
    async (input: LoginRequest) => {
      const session = await api.login(input);
      setCsrfToken(session.csrf_token);
      queryClient.setQueryData(queryKeys.auth.session, session);
    },
    [queryClient],
  );

  const setupAdmin = useCallback(
    async (input: SetupAdminRequest) => {
      await api.setupAdmin(input);
      await queryClient.invalidateQueries({ queryKey: queryKeys.setup });
    },
    [queryClient],
  );

  const logout = useCallback(async () => {
    await api.logout();
    setCsrfToken(null);
    queryClient.removeQueries({ queryKey: queryKeys.auth.sessions });
    await queryClient.invalidateQueries({ queryKey: queryKeys.auth.session });
  }, [queryClient]);

  const value = useMemo<AuthContextValue>(
    () => ({
      initialized,
      authenticated: sessionQuery.data?.authenticated === true,
      user: sessionQuery.data?.user ?? null,
      loading:
        setupQuery.isPending ||
        (initialized === true && sessionQuery.isPending),
      login,
      setupAdmin,
      logout,
      refreshSession,
    }),
    [
      initialized,
      login,
      logout,
      refreshSession,
      sessionQuery.data?.authenticated,
      sessionQuery.data?.user,
      sessionQuery.isPending,
      setupAdmin,
      setupQuery.isPending,
    ],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const value = useContext(AuthContext);

  if (!value) {
    throw new Error("useAuth must be used inside AuthProvider");
  }

  return value;
}
