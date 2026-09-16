/**
 * frontend/src/hooks/useCoverage.ts
 * ───────────────────────────────────
 * React Query hooks for the ATT&CK coverage API.
 * Built against proven /api/coverage/* routes (207 tests passing).
 *
 * Usage:
 *   const { data: rows }    = useCoverageMatrix();
 *   const { data: summary } = useCoverageSummary();
 *   const { mutate: refresh, isPending } = useRefreshCoverage();
 */
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { coverageApi, type CoverageListParams } from "@/lib/api";

const COVERAGE_KEY = ["coverage"] as const;
const SUMMARY_KEY  = ["coverage", "summary"] as const;

/**
 * Fetch the full ATT&CK coverage matrix.
 * Stale after 5 minutes — coverage changes only when rules change.
 */
export function useCoverageMatrix(params?: CoverageListParams) {
  return useQuery({
    queryKey: [...COVERAGE_KEY, params],
    queryFn:  () => coverageApi.getMatrix(params),
    staleTime: 5 * 60_000,
  });
}

/**
 * Fetch coverage aggregate stats for the dashboard header.
 * Lighter than the full matrix — just totals.
 */
export function useCoverageSummary() {
  return useQuery({
    queryKey: SUMMARY_KEY,
    queryFn:  coverageApi.getSummary,
    staleTime: 2 * 60_000,
    refetchInterval: 2 * 60_000,
  });
}

/**
 * Trigger a full coverage matrix recomputation.
 * Invalidates all coverage queries on success so the UI refreshes.
 */
export function useRefreshCoverage() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: coverageApi.refresh,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: COVERAGE_KEY });
    },
  });
}

/**
 * Convenience: group coverage rows by tactic for heatmap rendering.
 * Returns a Map<tactic, CoverageRow[]> from any coverage row array.
 */
export function groupByTactic(
  rows: ReturnType<typeof useCoverageMatrix>["data"],
): Map<string, NonNullable<typeof rows>[number][]> {
  const map = new Map<string, NonNullable<typeof rows>[number][]>();
  if (!rows) return map;
  for (const row of rows) {
    const t = row.tactic ?? "unknown";
    if (!map.has(t)) map.set(t, []);
    map.get(t)!.push(row);
  }
  return map;
}
