"use client";

/**
 * UserDrilldownSheet
 * ==================
 * Triggered by "Deep Audit →" in the user table.
 * Opens a side sheet that lazy-fetches full snapshot data and renders:
 *   - 30-day risk trend (RiskTrendChart)
 *   - Activity heatmap (ActivityHeatmap)
 *   - Latest SHAP explanation (from RiskSnapshot.contributingFeatures)
 *   - Evidence trail (ActivityLog)
 *   - Kill switch (LOCK / UNLOCK via handleSecurityAction)
 */

import { useState, useCallback } from "react";
import {
  Sheet, SheetContent, SheetHeader, SheetTitle, SheetTrigger,
} from "@/components/ui/sheet";
import { Badge } from "@/components/ui/badge";
import {
  Shield, Lock, Unlock, MapPin, Zap, Activity,
  TrendingUp, TrendingDown, Minus, Loader2,
} from "lucide-react";
import RiskTrendChart from "@/components/RiskTrendChart";
import ActivityHeatmap from "@/components/ActivityHeatmap";
import { handleSecurityAction } from "@/lib/actions/security";
import { useRouter } from "next/navigation";

// ── Types ─────────────────────────────────────────────────────────────────────

interface ContributingFeature {
  name: string;
  label: string;
  value: number;
  impact: number;
  direction: "increases_risk" | "decreases_risk";
}

interface UserRow {
  id: string;
  name: string | null;
  email: string;
  riskScore: number;
  isFlagged: boolean;
  status: string;
  lastLocation: string | null;
  snapshots: { riskScore: number; createdAt: Date | string }[];
}

interface SnapshotData {
  snapshots:     { riskScore: number; createdAt: string }[];
  riskSnapshots: {
    id: string;
    threatScore: number;
    ifScore: number | null;
    lstmScore: number | null;
    zScore: number | null;
    severity: string;
    contributingFeatures: ContributingFeature[];
    createdAt: string;
  }[];
  activityLogs: { id: string; action: string; description: string; createdAt: string }[];
}

// ── Sub-components ─────────────────────────────────────────────────────────────

function ScoreBar({ label, value }: { label: string; value: number | null }) {
  if (value === null) return null;
  return (
    <div>
      <div className="flex justify-between text-[10px] text-[#003478]/60 mb-1">
        <span className="font-semibold">{label}</span>
        <span className="font-mono">{value.toFixed(1)}</span>
      </div>
      <div className="h-1.5 bg-[#e8f1fb] rounded-full overflow-hidden">
        <div
          className={`h-full rounded-full transition-all ${
            value >= 70 ? "bg-red-500" : value >= 40 ? "bg-[#f7941d]" : "bg-[#003478]"
          }`}
          style={{ width: `${Math.min(value, 100)}%` }}
        />
      </div>
    </div>
  );
}

function SeverityBadge({ severity }: { severity: string }) {
  const cls: Record<string, string> = {
    CRITICAL: "bg-red-100 text-red-700 border-red-200",
    HIGH:     "bg-orange-100 text-orange-700 border-orange-200",
    MEDIUM:   "bg-yellow-100 text-yellow-700 border-yellow-200",
    LOW:      "bg-emerald-100 text-emerald-700 border-emerald-200",
  };
  return (
    <Badge className={`text-[9px] font-bold uppercase border ${cls[severity] ?? ""}`}>
      {severity}
    </Badge>
  );
}

// ── Main component ─────────────────────────────────────────────────────────────

export default function UserDrilldownSheet({ user }: { user: UserRow }) {
  const [open, setOpen] = useState(false);
  const [data, setData] = useState<SnapshotData | null>(null);
  const [loadingData, setLoadingData] = useState(false);
  const [locking, setLocking] = useState(false);
  const router = useRouter();

  const loadSnapshot = useCallback(async () => {
    if (data) return; // already loaded
    setLoadingData(true);
    try {
      const res = await fetch(`/api/users/${user.id}/snapshot`);
      if (res.ok) {
        const json = await res.json();
        setData({
          snapshots:     json.user.snapshots,
          riskSnapshots: json.user.riskSnapshots,
          activityLogs:  json.user.activityLogs,
        });
      }
    } finally {
      setLoadingData(false);
    }
  }, [user.id, data]);

  const handleOpen = (isOpen: boolean) => {
    setOpen(isOpen);
    if (isOpen) loadSnapshot();
  };

  const latestRisk = data?.riskSnapshots?.[0] ?? null;
  const topFeatures = latestRisk?.contributingFeatures ?? [];
  const geoAnomaly =
    user.lastLocation &&
    user.lastLocation !== "Mumbai, IN" &&
    user.lastLocation !== "Mumbai, India";

  return (
    <Sheet open={open} onOpenChange={handleOpen}>
      <SheetTrigger asChild>
        <button className="text-xs font-bold text-[#0066b3] hover:text-[#003478] underline underline-offset-4 transition-colors">
          Deep Audit →
        </button>
      </SheetTrigger>

      <SheetContent className="sm:max-w-xl bg-white border-l border-[#003478]/15 shadow-2xl overflow-y-auto p-0">
        {/* ── Sheet header ── */}
        <SheetHeader className="px-6 py-5 border-b border-[#003478]/10 bg-white sticky top-0 z-10">
          <div className="flex justify-between items-start">
            <div>
              <div className="flex items-center gap-2 mb-1">
                <div className="w-6 h-6 bg-[#003478] rounded flex items-center justify-center">
                  <Shield className="text-white" size={12} />
                </div>
                <SheetTitle className="text-base font-black text-[#003478]">
                  Identity Evidence
                </SheetTitle>
              </div>
              <p className="text-[10px] font-mono text-[#0066b3]/40 uppercase tracking-widest">
                {user.name ?? "—"} · {user.email}
              </p>
              <p className="text-[9px] text-[#003478]/30 font-mono mt-0.5">
                Session: {user.id.slice(-8)}
              </p>
            </div>

            {/* Kill Switch */}
            <form
              action={async () => {
                setLocking(true);
                await handleSecurityAction(
                  user.id,
                  user.status === "ACTIVE" ? "LOCK" : "UNLOCK",
                );
                setLocking(false);
                setOpen(false);
                router.refresh();
              }}
            >
              <button
                type="submit"
                disabled={locking}
                className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-bold transition-all shadow-sm disabled:opacity-60 ${
                  user.status === "ACTIVE"
                    ? "bg-red-600 text-white hover:bg-red-700"
                    : "bg-emerald-600 text-white hover:bg-emerald-700"
                }`}
              >
                {locking ? (
                  <Loader2 className="w-3 h-3 animate-spin" />
                ) : user.status === "ACTIVE" ? (
                  <Lock className="w-3 h-3" />
                ) : (
                  <Unlock className="w-3 h-3" />
                )}
                {user.status === "ACTIVE" ? "KILL SESSION" : "RESTORE ACCESS"}
              </button>
            </form>
          </div>

          {/* Risk summary chips */}
          <div className="flex items-center gap-2 mt-3">
            <span
              className={`text-sm font-black ${
                user.riskScore >= 90
                  ? "text-red-600"
                  : user.riskScore >= 70
                    ? "text-orange-600"
                    : user.riskScore >= 40
                      ? "text-yellow-600"
                      : "text-emerald-600"
              }`}
            >
              {user.riskScore}
              <span className="text-[10px] text-[#003478]/30 font-normal">/100</span>
            </span>
            {latestRisk && <SeverityBadge severity={latestRisk.severity} />}
            {user.isFlagged && (
              <span className="flex items-center gap-1 text-[9px] bg-[#f7941d] text-white font-black px-2 py-0.5 rounded animate-pulse">
                <Zap className="w-2.5 h-2.5" /> ANOMALY
              </span>
            )}
            {geoAnomaly && (
              <span className="flex items-center gap-1 text-[9px] bg-red-100 text-red-600 border border-red-200 font-bold px-2 py-0.5 rounded">
                <MapPin className="w-2.5 h-2.5" /> GEO-ANOMALY
              </span>
            )}
          </div>
        </SheetHeader>

        {/* ── Content ── */}
        <div className="px-6 space-y-8 pb-10">
          {loadingData && (
            <div className="flex items-center justify-center h-40">
              <Loader2 className="w-6 h-6 animate-spin text-[#003478]/40" />
            </div>
          )}

          {!loadingData && (
            <>
              {/* 30-day Trend Chart */}
              <div className="pt-6">
                <RiskTrendChart snapshots={data?.snapshots ?? user.snapshots} />
              </div>

              {/* Per-layer scores */}
              {latestRisk && (
                <div className="space-y-3">
                  <p className="text-[10px] font-bold text-[#003478]/40 uppercase tracking-widest">
                    Detection Layer Scores
                  </p>
                  <div className="grid grid-cols-3 gap-3">
                    <ScoreBar label="Isolation Forest" value={latestRisk.ifScore} />
                    <ScoreBar label="LSTM" value={latestRisk.lstmScore} />
                    <ScoreBar
                      label="Z-Score"
                      value={latestRisk.zScore !== null ? Math.abs(latestRisk.zScore ?? 0) * 20 : null}
                    />
                  </div>
                </div>
              )}

              {/* SHAP explanation */}
              {topFeatures.length > 0 && (
                <div>
                  <p className="text-[10px] font-bold text-[#003478]/40 uppercase tracking-widest mb-3">
                    Top Contributing Features (SHAP)
                  </p>
                  <div className="space-y-2.5">
                    {topFeatures.slice(0, 5).map((f, i) => (
                      <div key={i} className="flex items-center gap-3">
                        <div className="w-4 shrink-0">
                          {f.direction === "increases_risk" ? (
                            <TrendingUp size={12} className="text-red-500" />
                          ) : f.direction === "decreases_risk" ? (
                            <TrendingDown size={12} className="text-emerald-500" />
                          ) : (
                            <Minus size={12} className="text-gray-400" />
                          )}
                        </div>
                        <span className="text-[11px] text-[#003478]/70 w-40 truncate font-medium">
                          {f.label ?? f.name}
                        </span>
                        <div className="flex-1 h-2 bg-[#e8f1fb] rounded-full overflow-hidden">
                          <div
                            className={`h-full rounded-full transition-all ${
                              f.direction === "increases_risk"
                                ? "bg-red-500"
                                : "bg-emerald-500"
                            }`}
                            style={{ width: `${Math.min(Math.abs(f.impact) * 100, 100)}%` }}
                          />
                        </div>
                        <span className="text-[10px] font-mono text-[#003478]/40 w-10 text-right">
                          {f.value?.toFixed(2)}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Activity Heatmap */}
              <div>
                <ActivityHeatmap logs={data?.activityLogs ?? []} />
              </div>

              {/* Geo block */}
              <div className="grid grid-cols-2 gap-4">
                <div className="p-4 bg-[#003478] rounded-xl">
                  <h4 className="text-[10px] font-bold text-blue-300/70 uppercase flex items-center gap-2 mb-2">
                    <Zap className="w-3 h-3 text-[#f7941d]" /> AI Diagnostic
                  </h4>
                  <p className="text-xs text-blue-100 leading-relaxed">
                    {user.riskScore >= 90
                      ? "CRITICAL: Immediate intervention required. Multi-layer anomaly confirmed."
                      : user.riskScore >= 70
                        ? "HIGH RISK: Unusual behavioral drift detected across multiple signals."
                        : user.riskScore >= 40
                          ? "MEDIUM: Elevated activity. Monitor closely for escalation."
                          : "Behavior stable. Activity aligns with established identity clusters."}
                  </p>
                </div>
                <div className="p-4 bg-[#e8f1fb] rounded-xl border border-[#003478]/15">
                  <h4 className="text-[10px] font-bold text-[#003478]/50 uppercase flex items-center gap-2 mb-2">
                    <MapPin className="w-3 h-3 text-[#f7941d]" /> Access Geo
                  </h4>
                  <span className="text-sm font-bold text-[#003478]">
                    {user.lastLocation ?? "Mumbai, IN"}
                  </span>
                  {geoAnomaly && (
                    <Badge className="mt-2 bg-red-100 text-red-600 text-[8px] h-4 border-red-200 block w-fit">
                      ANOMALY
                    </Badge>
                  )}
                </div>
              </div>

              {/* Evidence trail */}
              {(data?.activityLogs?.length ?? 0) > 0 && (
                <div className="relative">
                  <h3 className="text-[10px] font-bold text-[#003478]/40 uppercase mb-5 tracking-widest">
                    Recent Evidence Trail
                  </h3>
                  <div className="absolute left-[19px] top-9 bottom-0 w-[2px] bg-[#003478]/10" />
                  <div className="space-y-6">
                    {(data?.activityLogs ?? []).slice(0, 12).map((log) => (
                      <div key={log.id} className="relative flex items-start gap-5">
                        <div
                          className={`mt-1 z-10 w-10 h-10 rounded-full flex items-center justify-center border-4 border-white shadow-sm shrink-0 ${
                            log.action.includes("DELETE") || log.action.includes("LOCK")
                              ? "bg-red-500"
                              : "bg-[#003478]"
                          }`}
                        >
                          <Activity className="w-4 h-4 text-white" />
                        </div>
                        <div className="space-y-0.5 pt-1">
                          <div className="flex items-center gap-2">
                            <h4 className="font-bold text-xs text-[#003478]">{log.action}</h4>
                            <span className="text-[9px] text-[#0066b3]/40 font-mono">
                              {new Date(log.createdAt).toLocaleTimeString([], {
                                hour: "2-digit",
                                minute: "2-digit",
                              })}
                            </span>
                          </div>
                          <p className="text-[11px] text-[#003478]/60 leading-snug">
                            {log.description}
                          </p>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </>
          )}
        </div>
      </SheetContent>
    </Sheet>
  );
}
