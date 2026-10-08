import { useEffect } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";

import { getOperation } from "../../lib/api/client";
import { queryKeys } from "../../lib/api/queryKeys";

function terminal(state: string | undefined) {
  return state === "succeeded" || state === "failed" || state === "degraded";
}

/**
 * Listen to authenticated operation SSE and refresh the canonical GET response.
 * Polling keeps working when EventSource is unavailable or disconnected.
 */
export function useOperation(operationId: string | null, pollMs = 2_500) {
  const queryClient = useQueryClient();
  const query = useQuery({
    queryKey: queryKeys.operations.detail(operationId ?? ""),
    queryFn: () => getOperation(operationId ?? ""),
    enabled: Boolean(operationId),
    refetchInterval: (current) =>
      terminal(current.state.data?.state) ? false : pollMs,
  });

  const complete = terminal(query.data?.state);

  useEffect(() => {
    if (!operationId || complete || typeof EventSource === "undefined") {
      return;
    }

    const source = new EventSource(
      `/api/v1/operations/${encodeURIComponent(operationId)}/events`,
      { withCredentials: true },
    );
    const refresh = () => {
      void queryClient.invalidateQueries({
        queryKey: queryKeys.operations.detail(operationId),
      });
    };
    const finish = () => {
      source.close();
      refresh();
    };

    for (const event of ["queued", "started", "progress"]) {
      source.addEventListener(event, refresh);
    }
    for (const event of ["succeeded", "failed", "degraded"]) {
      source.addEventListener(event, finish);
    }
    source.addEventListener("message", refresh);
    source.onerror = () => source.close();

    return () => source.close();
  }, [operationId, complete, queryClient]);

  return query;
}
