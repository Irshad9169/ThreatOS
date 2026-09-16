/**
 * frontend/src/hooks/usePurple.ts
 * ─────────────────────────────────
 * React Query hooks for the purple team and risk scoring API.
 * Built against proven /api/purple/* routes (388 tests passing).
 */
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  purpleApi,
  type ScoreV2Request,
  type ValidateChainRequest,
  type ValidateRequest,
} from "@/lib/api";

const RUNS_KEY = ["purple-runs"] as const;

/** Fetch purple team run history. */
export function usePurpleRuns(params?: { technique_id?: string; chain_id?: string }) {
  return useQuery({
    queryKey: [...RUNS_KEY, params],
    queryFn:  () => purpleApi.runs(params),
    staleTime: 30_000,
  });
}

/** Run a purple team validation for one technique. */
export function useValidateTechnique() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (req: ValidateRequest) => purpleApi.validate(req),
    onSuccess:  () => qc.invalidateQueries({ queryKey: RUNS_KEY }),
  });
}

/** Validate all techniques in an attack chain. */
export function useValidateChain() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (req: ValidateChainRequest) => purpleApi.validateChain(req),
    onSuccess:  () => qc.invalidateQueries({ queryKey: RUNS_KEY }),
  });
}

/** Compute a v2 risk score (pure calculation — no DB). */
export function useScoreV2() {
  return useMutation({
    mutationFn: (req: ScoreV2Request) => purpleApi.scoreV2(req),
  });
}
