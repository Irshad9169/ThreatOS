/**
 * frontend/src/hooks/useAlertStream.ts
 * ──────────────────────────────────────
 * WebSocket hook for real-time alert feed.
 *
 * The ingest worker publishes to the Redis pubsub channel
 * "threatos:alerts:live" after each batch.  A FastAPI WebSocket
 * endpoint (Phase 2, ws_router.py) subscribes to that channel and
 * fans the messages out to connected browser clients.
 *
 * This hook manages the WebSocket lifecycle and hands new alerts
 * to React Query's cache so the useAlerts hook auto-refreshes.
 *
 * Usage:
 *   // In your root component (e.g. App.tsx):
 *   useAlertStream();   // connect once at app level
 *
 *   // In a dashboard panel:
 *   const { data: alerts } = useAlerts();  // auto-updated by stream
 */
import { useEffect, useRef } from "react";
import { useQueryClient } from "@tanstack/react-query";
import type { Alert } from "@/lib/api";

const WS_URL = (
  (window.location.protocol === "https:" ? "wss://" : "ws://") +
  window.location.host +
  "/ws/alerts"
);

/** How long to wait before attempting to reconnect (ms). */
const RECONNECT_DELAY_MS = 3_000;

/**
 * Connect to the alert WebSocket stream.
 * Inserts incoming alerts into the React Query cache so all
 * `useAlerts()` subscribers see them without a full re-fetch.
 * Reconnects automatically on disconnect.
 */
export function useAlertStream(): void {
  const queryClient  = useQueryClient();
  const wsRef        = useRef<WebSocket | null>(null);
  const reconnectRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    let destroyed = false;

    function connect() {
      if (destroyed) return;

      const ws = new WebSocket(WS_URL);
      wsRef.current = ws;

      ws.onmessage = (event) => {
        try {
          const alert: Alert = JSON.parse(event.data);

          // Prepend the new alert into every cached alerts list
          queryClient.setQueriesData<Alert[]>(
            { queryKey: ["alerts"] },
            (old) => (old ? [alert, ...old] : [alert]),
          );
        } catch {
          // Ignore unparseable messages
        }
      };

      ws.onclose = () => {
        if (!destroyed) {
          reconnectRef.current = setTimeout(connect, RECONNECT_DELAY_MS);
        }
      };

      ws.onerror = () => {
        ws.close();   // triggers onclose → reconnect
      };
    }

    connect();

    return () => {
      destroyed = true;
      if (reconnectRef.current) clearTimeout(reconnectRef.current);
      if (wsRef.current) wsRef.current.close();
    };
  }, [queryClient]);
}
