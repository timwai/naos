import { useQuery } from "@tanstack/react-query";

import { getSession, getSetupStatus } from "../../lib/api/client";
import { queryKeys } from "../../lib/api/queryKeys";

export function useSession() {
  return useQuery({
    queryKey: queryKeys.auth.session(),
    queryFn: ({ signal }) => getSession(signal),
    retry: false,
    refetchInterval: 30_000,
    refetchOnWindowFocus: "always",
  });
}

export function useSetupStatus() {
  return useQuery({
    queryKey: queryKeys.auth.setup(),
    queryFn: getSetupStatus,
  });
}
