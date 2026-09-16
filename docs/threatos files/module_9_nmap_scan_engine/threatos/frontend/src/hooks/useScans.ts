/**
 * frontend/src/hooks/useScans.ts
 * ────────────────────────────────
 * React Query hooks for the Nmap scan engine API.
 * Built against proven /api/scans/* routes (435 tests passing).
 *
 * Note: POST /api/scans blocks until Nmap finishes — long-running
 * mutations. Show a loading spinner while isPending is true.
 *
 * Usage:
 *   const { data: scans }  = useScans();
 *   const { mutate: scan, isPending } = useRunScan();
 */
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  scansApi,
  type ScanRequest,
  type ScanStatus,
} from "@/lib/api";

const SCANS_KEY = ["scans"] as const;

/** Fetch scan history. */
export function useScans(params?: { target?: string; status?: ScanStatus }) {
  return useQuery({
    queryKey: [...SCANS_KEY, params],
    queryFn:  () => scansApi.list(params),
    refetchInterval: 10_000,
  });
}

/** Fetch a single scan by ID, polling until it leaves 'running' state. */
export function useScan(id: string | undefined) {
  return useQuery({
    queryKey: [...SCANS_KEY, id],
    queryFn:  () => scansApi.get(id!),
    enabled:  id !== undefined,
    refetchInterval: (query) => {
      const status = query.state.data?.status;
      return status === "running" || status === "pending" ? 2_000 : false;
    },
  });
}

/** Create and immediately run a scan (blocking until complete). */
export function useRunScan() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (req: ScanRequest) => scansApi.run(req),
    onSuccess:  () => qc.invalidateQueries({ queryKey: SCANS_KEY }),
  });
}

/** Create a pending scan without running it. */
export function useCreateScan() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (req: ScanRequest) => scansApi.create(req),
    onSuccess:  () => qc.invalidateQueries({ queryKey: SCANS_KEY }),
  });
}

/** Execute an existing pending scan. */
export function useExecuteScan() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, timeout }: { id: string; timeout?: number }) =>
      scansApi.execute(id, timeout),
    onSuccess: () => qc.invalidateQueries({ queryKey: SCANS_KEY }),
  });
}
