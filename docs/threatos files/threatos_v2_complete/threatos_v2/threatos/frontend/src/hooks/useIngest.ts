/**
 * frontend/src/hooks/useIngest.ts
 * ────────────────────────────────
 * React Query mutations for the ingest API.
 * Built against the proven /api/ingest/* routes (37 tests passing).
 *
 * Usage in any component:
 *   const { mutate, isPending, isError, data } = useIngestEvent();
 *   mutate({ log_source: "json", payload: { hostname: "srv01" } });
 */
import { useMutation } from "@tanstack/react-query";
import { ingestApi, type IngestRequest } from "@/lib/api";

/**
 * Mutation hook for POST /api/ingest/event
 * Returns the IngestResponse on success (status, event_id, hash).
 */
export function useIngestEvent() {
  return useMutation({
    mutationFn: (req: IngestRequest) => ingestApi.single(req),
  });
}

/**
 * Mutation hook for POST /api/ingest/batch
 * Returns BatchIngestResponse with queued/failed counts + event_ids.
 */
export function useIngestBatch() {
  return useMutation({
    mutationFn: (events: IngestRequest[]) => ingestApi.batch(events),
  });
}

/**
 * Mutation hook for POST /api/ingest/syslog
 * Accepts a raw syslog line string.
 */
export function useIngestSyslog() {
  return useMutation({
    mutationFn: (rawLine: string) => ingestApi.syslog(rawLine),
  });
}
