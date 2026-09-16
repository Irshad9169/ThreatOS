/**
 * frontend/src/hooks/useRules.ts
 * ────────────────────────────────
 * React Query hooks for the detection rules API.
 * Built against proven /api/rules/* routes (109 tests passing).
 *
 * Usage:
 *   const { data: rules, isLoading } = useRules();
 *   const { mutate: createRule } = useCreateRule();
 *   const { mutate: toggleRule } = useToggleRule();
 */
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { rulesApi, type RuleCreate } from "@/lib/api";

const RULES_KEY = ["rules"] as const;

/**
 * Fetch all enabled detection rules.
 * Pass enabledOnly=false to include disabled rules.
 */
export function useRules(enabledOnly = true) {
  return useQuery({
    queryKey: [...RULES_KEY, { enabledOnly }],
    queryFn: () => rulesApi.list(enabledOnly),
    staleTime: 60_000,    // rules change infrequently — cache for 1 minute
  });
}

/**
 * Fetch a single rule by ID.
 * Only fetches when id is defined.
 */
export function useRule(id: string | undefined) {
  return useQuery({
    queryKey: [...RULES_KEY, id],
    queryFn: () => rulesApi.get(id!),
    enabled: id !== undefined,
  });
}

/**
 * Mutation to create a new detection rule.
 * Invalidates the rules list on success so the table refreshes.
 */
export function useCreateRule() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (rule: RuleCreate) => rulesApi.create(rule),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: RULES_KEY });
    },
  });
}

/**
 * Mutation to toggle a rule's enabled state.
 * Invalidates the rules list on success.
 */
export function useToggleRule() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => rulesApi.toggle(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: RULES_KEY });
    },
  });
}
