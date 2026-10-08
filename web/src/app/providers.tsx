import {
  QueryClient,
  QueryClientProvider,
} from "@tanstack/react-query";
import { useEffect, useState, type PropsWithChildren } from "react";
import { SESSION_EXPIRED_EVENT } from "../lib/api/client";
import { queryKeys } from "../lib/api/queryKeys";

export function AppProviders({ children }: PropsWithChildren) {
  const [queryClient] = useState(
    () =>
      new QueryClient({
        defaultOptions: {
          queries: {
            retry: 1,
            refetchOnWindowFocus: false,
            staleTime: 10_000,
          },
        },
      }),
  );

  useEffect(() => {
    const onSessionExpired = () => {
      // Clear cached private data before the auth guard redirects to login.
      void queryClient.cancelQueries().then(() => {
        queryClient.clear();
        queryClient.setQueryData(queryKeys.auth.session(), {
          authenticated: false,
          user: null,
          csrf_token: null,
        });
      });
    };
    window.addEventListener(SESSION_EXPIRED_EVENT, onSessionExpired);
    return () => window.removeEventListener(SESSION_EXPIRED_EVENT, onSessionExpired);
  }, [queryClient]);

  return (
    <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
  );
}
