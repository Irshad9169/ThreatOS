/**
 * frontend/src/hooks/useAlerts.ts
 * ────────────────────────────────
 * React Query hooks for the alerts API.
 * Built against proven /api/alerts/* routes (151 tests passing).
 *
 * Usage:
 *   const { data: alerts, isLoading } = useAlerts({ status: "open" });
 *   const { mutate: updateStatus } = useUpdateAlertStatus();
 */
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  alertsApi,
  type Alert,
  type AlertListParams,
  type AlertStatus,
} from "@/lib/api";

const ALERTS_KEY = ["alerts"] as const;

/**
 * Fetch a filtered list of alerts.
 * Refetches every 15 seconds to catch new alerts without WebSocket.
 * (Phase 2 adds a WebSocket layer on top for sub-second updates.)
 */
export function useAlerts(params?: AlertListParams) {
  return useQuery({
    queryKey: [...ALERTS_KEY, params],
    queryFn: () => alertsApi.list(params),
    refetchInterval: 15_000,
    staleTime: 5_000,
  });
}

/**
 * Fetch a single alert by ID.
 * Skips the query when id is undefined.
 */
export function useAlert(id: string | undefined) {
  return useQuery({
    queryKey: [...ALERTS_KEY, id],
    queryFn: () => alertsApi.get(id!),
    enabled: id !== undefined,
  });
}

/**
 * Update an alert's status.
 * Optimistically updates the local cache then invalidates
 * so the list re-fetches with the new status from the server.
 */
export function useUpdateAlertStatus() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({ id, status }: { id: string; status: AlertStatus }) =>
      alertsApi.updateStatus(id, status),

    onMutate: async ({ id, status }) => {
      // Cancel in-flight refetches to avoid overwriting the optimistic update
      await queryClient.cancelQueries({ queryKey: ALERTS_KEY });

      // Snapshot current data for rollback on error
      const snapshot = queryClient.getQueryData(ALERTS_KEY);

      // Optimistically update matching alerts in all cached query results
      queryClient.setQueriesData(
        { queryKey: ALERTS_KEY },
        (old: Alert[] | undefined) =>
          old?.map((a) => (a.id === id ? { ...a, status } : a)),
      );

      return { snapshot };
    },

    onError: (_err, _vars, context) => {
      // Roll back to snapshot on error
      if (context?.snapshot) {
        queryClient.setQueryData(ALERTS_KEY, context.snapshot);
      }
    },

    onSettled: () => {
      // Always refetch after mutation so cache matches server
      queryClient.invalidateQueries({ queryKey: ALERTS_KEY });
    },
  });
}
