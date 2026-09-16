/**
 * frontend/src/hooks/useAssets.ts
 * ─────────────────────────────────
 * React Query hooks for the asset registry API.
 * Built against proven /api/assets/* routes (262 tests passing).
 *
 * Usage:
 *   const { data: assets }     = useAssets();
 *   const { mutate: create }   = useCreateAsset();
 *   const { mutate: setCrit }  = useUpdateCriticality();
 */
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  assetsApi,
  type Asset,
  type AssetCreatePayload,
  type AssetListParams,
} from "@/lib/api";

const ASSETS_KEY = ["assets"] as const;

/** Fetch the full asset list with optional filters. */
export function useAssets(params?: AssetListParams) {
  return useQuery({
    queryKey: [...ASSETS_KEY, params],
    queryFn:  () => assetsApi.list(params),
    staleTime: 60_000,   // assets change infrequently
  });
}

/** Fetch a single asset by ID. */
export function useAsset(id: string | undefined) {
  return useQuery({
    queryKey: [...ASSETS_KEY, id],
    queryFn:  () => assetsApi.get(id!),
    enabled:  id !== undefined,
  });
}

/**
 * Create a new asset.
 * Returns 409 if hostname already exists — callers must handle the error.
 */
export function useCreateAsset() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (data: AssetCreatePayload) => assetsApi.create(data),
    onSuccess:  () => queryClient.invalidateQueries({ queryKey: ASSETS_KEY }),
  });
}

/**
 * Create-or-update an asset by hostname.
 * Safer than useCreateAsset when the hostname may already exist.
 */
export function useUpsertAsset() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (data: AssetCreatePayload) => assetsApi.upsert(data),
    onSuccess:  () => queryClient.invalidateQueries({ queryKey: ASSETS_KEY }),
  });
}

/**
 * Update the criticality tier of an existing asset.
 * Optimistically updates the cached list so the UI responds instantly.
 */
export function useUpdateCriticality() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({
      id,
      criticality,
    }: { id: string; criticality: 1 | 2 | 3 | 4 }) =>
      assetsApi.updateCriticality(id, criticality),

    onMutate: async ({ id, criticality }) => {
      await queryClient.cancelQueries({ queryKey: ASSETS_KEY });
      const snapshot = queryClient.getQueriesData({ queryKey: ASSETS_KEY });

      queryClient.setQueriesData(
        { queryKey: ASSETS_KEY },
        (old: Asset[] | undefined) =>
          old?.map((a) => (a.id === id ? { ...a, criticality } : a)),
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
      queryClient.invalidateQueries({ queryKey: ASSETS_KEY }),
  });
}
