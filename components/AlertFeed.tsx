"use client";

/**
 * AlertFeed
 * =========
 * Connects to /api/alerts/stream (SSE) and displays live alerts as they
 * arrive via pg_notify from the Kafka alert consumer.
 * Falls back gracefully if the stream is unavailable.
 */

import { useEffect, useRef, useState } from "react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

interface LiveAlert {
  alertId: string;
  userId: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  riskScore: number;
  explanation: string;
  timestamp: string;
}

const SEVERITY_STYLES: Record<string, string> = {
  CRITICAL: "bg-red-100 text-red-700 border-red-200",
  HIGH:     "bg-orange-100 text-orange-700 border-orange-200",
  MEDIUM:   "bg-yellow-100 text-yellow-700 border-yellow-200",
  LOW:      "bg-blue-100 text-blue-700 border-blue-200",
};

function timeAgo(iso: string): string {
  const diff = Math.floor((Date.now() - new Date(iso).getTime()) / 1000);
  if (diff < 60) return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  return `${Math.floor(diff / 3600)}h ago`;
}

export default function AlertFeed({ maxItems = 20 }: { maxItems?: number }) {
  const [alerts, setAlerts] = useState<LiveAlert[]>([]);
  const [connected, setConnected] = useState(false);
  const esRef = useRef<EventSource | null>(null);

  useEffect(() => {
    const es = new EventSource("/api/alerts/stream");
    esRef.current = es;

    es.onopen = () => setConnected(true);

    es.onmessage = (e) => {
      try {
        const alert: LiveAlert = JSON.parse(e.data);
        if (!alert.alertId) return; // heartbeat / error message
        setAlerts((prev) => [alert, ...prev].slice(0, maxItems));
      } catch {}
    };

    es.onerror = () => {
      setConnected(false);
      // EventSource auto-reconnects; no manual retry needed
    };

    return () => {
      es.close();
    };
  }, [maxItems]);

  return (
    <Card className="border border-[#003478]/10 shadow-sm">
      <CardHeader className="pb-2 flex flex-row items-center justify-between">
        <CardTitle className="text-sm font-semibold text-[#003478]">
          Live Alert Feed
        </CardTitle>
        <span className={`flex items-center gap-1.5 text-[11px] font-mono ${connected ? "text-green-600" : "text-gray-400"}`}>
          <span className={`w-1.5 h-1.5 rounded-full ${connected ? "bg-green-500 animate-pulse" : "bg-gray-300"}`} />
          {connected ? "live" : "connecting…"}
        </span>
      </CardHeader>

      <CardContent className="p-0">
        {alerts.length === 0 ? (
          <p className="text-[12px] text-[#003478]/40 text-center py-6">
            No alerts yet — waiting for events…
          </p>
        ) : (
          <ul className="divide-y divide-[#003478]/5 max-h-[420px] overflow-y-auto">
            {alerts.map((a) => (
              <li key={a.alertId} className="flex items-start gap-3 px-4 py-3">
                <Badge
                  className={`text-[10px] px-1.5 py-0.5 rounded-md border font-semibold shrink-0 ${SEVERITY_STYLES[a.severity] ?? ""}`}
                >
                  {a.severity}
                </Badge>
                <div className="flex-1 min-w-0">
                  <p className="text-[12px] font-medium text-[#003478] truncate">
                    {a.userId}
                  </p>
                  <p className="text-[11px] text-[#003478]/60 truncate">
                    Risk {a.riskScore} — {a.explanation || "Anomalous behaviour detected"}
                  </p>
                </div>
                <span className="text-[10px] text-[#003478]/30 font-mono shrink-0">
                  {timeAgo(a.timestamp)}
                </span>
              </li>
            ))}
          </ul>
        )}
      </CardContent>
    </Card>
  );
}
