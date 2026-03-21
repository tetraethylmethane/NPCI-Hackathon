"use client";

import { useEffect, useState, useCallback } from "react";
import { Badge } from "@/components/ui/badge";
import {
  AlertCircle, ChevronDown, ChevronRight, RefreshCw,
  Lock, TrendingUp, TrendingDown, Minus,
} from "lucide-react";

// ── Types ──────────────────────────────────────────────────────────────────────

interface ContributingFeature {
  name: string;
  label: string;
  value: number;
  impact: number;
  direction: "increases_risk" | "decreases_risk";
}

interface AlertUser {
  id: string;
  name: string | null;
  email: string;
  status: string;
  lastLocation: string | null;
}

interface Alert {
  id: string;
  riskScore: number;
  severity: string;
  confidence: number;
  status: string;
  explanation: ContributingFeature[] | null;
  createdAt: string;
  user: AlertUser;
}

// ── Helpers ────────────────────────────────────────────────────────────────────

const SEVERITY_STYLE: Record<string, string> = {
  CRITICAL: "bg-red-100 text-red-700 border-red-200",
  HIGH:     "bg-orange-100 text-orange-700 border-orange-200",
  MEDIUM:   "bg-yellow-100 text-yellow-700 border-yellow-200",
  LOW:      "bg-emerald-100 text-emerald-700 border-emerald-200",
};

const SEVERITY_DOT: Record<string, string> = {
  CRITICAL: "bg-red-500",
  HIGH:     "bg-orange-500",
  MEDIUM:   "bg-yellow-500",
  LOW:      "bg-emerald-500",
};

const IMPACT_BAR_COLOR = (dir: string) =>
  dir === "increases_risk" ? "bg-red-500" : "bg-emerald-500";

function timeAgo(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime();
  const m = Math.floor(diff / 60_000);
  if (m < 1) return "just now";
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

// ── Main component ─────────────────────────────────────────────────────────────

const FILTERS = ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"] as const;
type Filter = (typeof FILTERS)[number];

export default function AlertsPanel() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [filter, setFilter] = useState<Filter>("ALL");
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [countdown, setCountdown] = useState(60);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);

  const fetchAlerts = useCallback(async () => {
    try {
      const url =
        filter === "ALL"
          ? "/api/alerts?limit=50"
          : `/api/alerts?severity=${filter}&limit=50`;
      const res = await fetch(url);
      if (!res.ok) return;
      const data = await res.json();
      setAlerts(data.alerts ?? []);
      setLastUpdated(new Date());
      setCountdown(60);
    } catch {
      // silent — keep stale data
    } finally {
      setLoading(false);
    }
  }, [filter]);

  // re-fetch whenever filter changes
  useEffect(() => {
    setLoading(true);
    fetchAlerts();
  }, [fetchAlerts]);

  // 60-second auto-refresh + countdown ticker
  useEffect(() => {
    const interval = setInterval(() => {
      setCountdown((c) => {
        if (c <= 1) {
          fetchAlerts();
          return 60;
        }
        return c - 1;
      });
    }, 1_000);
    return () => clearInterval(interval);
  }, [fetchAlerts]);

  return (
    <div className="bg-white rounded-xl border border-[#003478]/10 shadow-sm overflow-hidden">
      {/* Panel header */}
      <div className="bg-[#003478] px-6 py-4 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <AlertCircle size={14} className="text-[#f7941d]" />
          <span className="text-white text-sm font-bold uppercase tracking-wider">
            Anomaly Alerts
          </span>
          {alerts.length > 0 && (
            <span className="bg-[#f7941d] text-white text-[10px] font-black px-2 py-0.5 rounded-full">
              {alerts.length}
            </span>
          )}
        </div>
        <div className="flex items-center gap-3">
          {lastUpdated && (
            <span className="text-blue-300/60 text-[10px] font-mono">
              Refreshes in {countdown}s
            </span>
          )}
          <button
            onClick={fetchAlerts}
            className="p-1.5 rounded hover:bg-white/10 transition-colors"
            title="Refresh now"
          >
            <RefreshCw size={12} className="text-blue-200" />
          </button>
        </div>
      </div>

      {/* Severity filter chips */}
      <div className="flex gap-2 px-6 py-3 border-b border-[#003478]/8 bg-[#e8f1fb]/40">
        {FILTERS.map((f) => (
          <button
            key={f}
            onClick={() => setFilter(f)}
            className={`px-3 py-1 rounded-full text-[11px] font-bold uppercase tracking-wide transition-all border ${
              filter === f
                ? "bg-[#003478] text-white border-[#003478]"
                : "bg-white text-[#003478]/60 border-[#003478]/20 hover:border-[#003478]/40"
            }`}
          >
            {f}
          </button>
        ))}
      </div>

      {/* Alert table */}
      {loading ? (
        <div className="flex items-center justify-center h-40 text-[#003478]/40 text-sm">
          Loading alerts…
        </div>
      ) : alerts.length === 0 ? (
        <div className="flex flex-col items-center justify-center h-40 gap-2">
          <div className="w-10 h-10 rounded-full bg-emerald-50 flex items-center justify-center">
            <AlertCircle size={18} className="text-emerald-500" />
          </div>
          <p className="text-sm text-[#003478]/50 font-medium">
            No active alerts{filter !== "ALL" ? ` for severity: ${filter}` : ""}
          </p>
        </div>
      ) : (
        <div className="divide-y divide-[#003478]/5">
          {alerts.map((alert) => (
            <div key={alert.id}>
              {/* Main row */}
              <div
                className="grid grid-cols-[1fr_auto_auto_auto_auto_auto] items-center gap-4 px-6 py-3.5 hover:bg-[#e8f1fb]/30 transition-colors cursor-pointer"
                onClick={() =>
                  setExpandedId(expandedId === alert.id ? null : alert.id)
                }
              >
                {/* User */}
                <div className="min-w-0">
                  <div className="flex items-center gap-2">
                    <div
                      className={`w-1.5 h-1.5 rounded-full shrink-0 ${SEVERITY_DOT[alert.severity] ?? "bg-gray-400"}`}
                    />
                    <span className="font-semibold text-[#003478] text-sm truncate">
                      {alert.user.name ?? alert.user.email}
                    </span>
                    {alert.user.status === "LOCKED" && (
                      <Lock size={11} className="text-red-500 shrink-0" />
                    )}
                  </div>
                  <span className="text-[11px] text-[#0066b3]/50 font-mono ml-3.5">
                    {alert.user.email}
                  </span>
                </div>

                {/* Severity */}
                <Badge
                  className={`text-[10px] font-bold border uppercase px-2 ${SEVERITY_STYLE[alert.severity] ?? ""}`}
                >
                  {alert.severity}
                </Badge>

                {/* Threat score */}
                <div className="text-center">
                  <span
                    className={`text-sm font-black ${
                      alert.riskScore >= 90
                        ? "text-red-600"
                        : alert.riskScore >= 70
                          ? "text-orange-600"
                          : alert.riskScore >= 40
                            ? "text-yellow-600"
                            : "text-emerald-600"
                    }`}
                  >
                    {alert.riskScore}
                  </span>
                  <span className="text-[10px] text-[#003478]/30">/100</span>
                </div>

                {/* Confidence */}
                <div className="flex items-center gap-1.5 w-24">
                  <div className="flex-1 h-1.5 bg-[#e8f1fb] rounded-full overflow-hidden">
                    <div
                      className="h-full bg-[#003478] rounded-full transition-all"
                      style={{ width: `${Math.round(alert.confidence * 100)}%` }}
                    />
                  </div>
                  <span className="text-[10px] text-[#003478]/50 w-8 text-right font-mono">
                    {Math.round(alert.confidence * 100)}%
                  </span>
                </div>

                {/* Time */}
                <span className="text-[11px] text-[#003478]/40 whitespace-nowrap">
                  {timeAgo(alert.createdAt)}
                </span>

                {/* Expand toggle */}
                <button className="text-[#003478]/30 hover:text-[#003478] transition-colors">
                  {expandedId === alert.id ? (
                    <ChevronDown size={14} />
                  ) : (
                    <ChevronRight size={14} />
                  )}
                </button>
              </div>

              {/* Expanded: SHAP feature explanation */}
              {expandedId === alert.id && (
                <div className="px-6 pb-5 pt-1 bg-[#e8f1fb]/25 border-t border-[#003478]/5">
                  <p className="text-[10px] text-[#003478]/40 uppercase font-semibold tracking-widest mb-3">
                    Top contributing features (SHAP)
                  </p>
                  {!alert.explanation || alert.explanation.length === 0 ? (
                    <p className="text-xs text-[#003478]/40 italic">
                      No SHAP explanation available for this alert.
                    </p>
                  ) : (
                    <div className="space-y-2.5">
                      {alert.explanation.slice(0, 5).map((feat, i) => (
                        <div key={i} className="flex items-center gap-3">
                          <div className="w-4 shrink-0">
                            {feat.direction === "increases_risk" ? (
                              <TrendingUp size={12} className="text-red-500" />
                            ) : feat.direction === "decreases_risk" ? (
                              <TrendingDown size={12} className="text-emerald-500" />
                            ) : (
                              <Minus size={12} className="text-gray-400" />
                            )}
                          </div>
                          <span className="text-[11px] text-[#003478]/70 w-44 truncate font-medium">
                            {feat.label ?? feat.name}
                          </span>
                          <div className="flex-1 h-2 bg-[#e8f1fb] rounded-full overflow-hidden">
                            <div
                              className={`h-full rounded-full transition-all ${IMPACT_BAR_COLOR(feat.direction)}`}
                              style={{
                                width: `${Math.min(Math.abs(feat.impact) * 100, 100)}%`,
                              }}
                            />
                          </div>
                          <span className="text-[10px] font-mono text-[#003478]/50 w-10 text-right">
                            {feat.value?.toFixed(2)}
                          </span>
                        </div>
                      ))}
                    </div>
                  )}

                  {/* Location anomaly */}
                  {alert.user.lastLocation &&
                    alert.user.lastLocation !== "Mumbai, IN" && (
                      <div className="mt-3 flex items-center gap-2">
                        <Badge className="bg-red-100 text-red-600 border-red-200 text-[9px] uppercase font-bold">
                          Geo Anomaly
                        </Badge>
                        <span className="text-[11px] text-[#003478]/60">
                          Last seen: {alert.user.lastLocation}
                        </span>
                      </div>
                    )}
                </div>
              )}
            </div>
          ))}
        </div>
      )}

      {/* Column header hint */}
      {!loading && alerts.length > 0 && (
        <div className="grid grid-cols-[1fr_auto_auto_auto_auto_auto] gap-4 px-6 py-2 border-t border-[#003478]/5 bg-[#e8f1fb]/20">
          {["User", "Severity", "Score", "Confidence", "Time", ""].map((h) => (
            <span
              key={h}
              className="text-[9px] uppercase tracking-widest text-[#003478]/30 font-semibold"
            >
              {h}
            </span>
          ))}
        </div>
      )}
    </div>
  );
}
