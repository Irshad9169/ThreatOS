/**
 * frontend/src/hooks/useChains.ts
 * ─────────────────────────────────
 * React Query hooks for the attack chain API.
 * Built against proven /api/chains/* routes (331 tests passing).
 *
 * Usage:
 *   const { data: chains }   = useChains({ is_multi_stage: true });
 *   const { mutate: correlate } = useCorrelate();
 *   const { mutate: setStatus } = useUpdateChainStatus();
 */
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  chainsApi,
  type AttackChain,
  type ChainListParams,
  type ChainStatus,
  type CorrelateRequest,
} from "@/lib/api";

const CHAINS_KEY = ["chains"] as const;

/** Fetch attack chains with optional filters. */
export function useChains(params?: ChainListParams) {
  return useQuery({
    queryKey: [...CHAINS_KEY, params],
    queryFn:  () => chainsApi.list(params),
    refetchInterval: 30_000,   // chains change as new alerts arrive
    staleTime: 10_000,
  });
}

/** Fetch a single chain by ID. */
export function useChain(id: string | undefined) {
  return useQuery({
    queryKey: [...CHAINS_KEY, id],
    queryFn:  () => chainsApi.get(id!),
    enabled:  id !== undefined,
  });
}

/**
 * Trigger correlation for one host.
 * Invalidates the chains list on success.
 */
export function useCorrelate() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (req: CorrelateRequest) => chainsApi.correlate(req),
    onSuccess:  () => queryClient.invalidateQueries({ queryKey: CHAINS_KEY }),
  });
}

/**
 * Update the status of an attack chain.
 * Optimistically patches the list cache then invalidates.
 */
export function useUpdateChainStatus() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ id, status }: { id: string; status: ChainStatus }) =>
      chainsApi.updateStatus(id, status),

    onMutate: async ({ id, status }) => {
      await queryClient.cancelQueries({ queryKey: CHAINS_KEY });
      const snapshot = queryClient.getQueriesData({ queryKey: CHAINS_KEY });
      queryClient.setQueriesData(
        { queryKey: CHAINS_KEY },
        (old: AttackChain[] | undefined) =>
          old?.map((c) => (c.id === id ? { ...c, status } : c)),
      );
      return { snapshot };
    },

    onError: (_err, _vars, ctx) => {
      if (ctx?.snapshot) {
        for (const [key, data] of ctx.snapshot) {
          queryClient.setQueryData(key, data);
        }
      }
    },

    onSettled: () =>
      queryClient.invalidateQueries({ queryKey: CHAINS_KEY }),
  });
}
