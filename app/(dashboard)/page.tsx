export const dynamic = "force-dynamic";

import { prisma } from "@/lib/prisma";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import {
  Table, TableBody, TableCell, TableHead,
  TableHeader, TableRow,
} from "@/components/ui/table";
import {
  AlertCircle, ShieldCheck, Activity, RefreshCw,
  Zap, Lock, Shield, Clock, Users,
} from "lucide-react";
import { revalidatePath } from "next/cache";
import AlertsPanel from "@/components/AlertsPanel";
import UserDrilldownSheet from "@/components/UserDrilldownSheet";

// ── Helpers ────────────────────────────────────────────────────────────────────

function severityColor(level: string) {
  if (level === "CRITICAL") return "text-red-600 bg-red-50 border-red-200";
  if (level === "HIGH")     return "text-orange-600 bg-orange-50 border-orange-200";
  if (level === "MEDIUM")   return "text-yellow-600 bg-yellow-50 border-yellow-200";
  return "text-emerald-600 bg-emerald-50 border-emerald-200";
}

function riskLevelBadgeStyle(level: string) {
  if (level === "CRITICAL") return "bg-red-600 text-white";
  if (level === "HIGH")     return "bg-orange-500 text-white";
  if (level === "MEDIUM")   return "bg-yellow-500 text-white";
  return "bg-emerald-500 text-white";
}

function timeAgo(d: Date): string {
  const diff = Date.now() - d.getTime();
  const m = Math.floor(diff / 60_000);
  if (m < 1) return "just now";
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

// ── Page ───────────────────────────────────────────────────────────────────────

export default async function DashboardPage() {
  // ── Server-side data ──────────────────────────────────────────────────────
  const [users, alertGroups, recentAlerts] = await Promise.all([
    prisma.user.findMany({
      orderBy: { riskScore: "desc" },
      select: {
        id: true,
        name: true,
        email: true,
        riskScore: true,
        isFlagged: true,
        status: true,
        lastLocation: true,
        lastAnalyzed: true,
        snapshots: {
          orderBy: { createdAt: "desc" },
          take: 7,
          select: { riskScore: true, createdAt: true },
        },
      },
    }),
    prisma.alert.groupBy({
      by: ["severity"],
      where: { status: { in: ["OPEN", "ASSIGNED", "ACKNOWLEDGED"] } },
      _count: { id: true },
    }),
    prisma.alert.findMany({
      where: { status: { in: ["OPEN", "ASSIGNED", "ACKNOWLEDGED"] } },
      orderBy: { createdAt: "desc" },
      take: 10,
      include: { user: { select: { name: true, email: true } } },
    }),
  ]);

  const countBySeverity: Record<string, number> = {
    CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0,
  };
  for (const g of alertGroups) countBySeverity[g.severity] = g._count.id;
  const totalActiveAlerts = alertGroups.reduce((s, g) => s + g._count.id, 0);

  let systemRiskLevel = "LOW";
  if (countBySeverity.CRITICAL > 0)      systemRiskLevel = "CRITICAL";
  else if (countBySeverity.HIGH > 0)     systemRiskLevel = "HIGH";
  else if (countBySeverity.MEDIUM > 0)   systemRiskLevel = "MEDIUM";

  const flaggedCount = users.filter((u) => u.isFlagged).length;

  // ── Server action ─────────────────────────────────────────────────────────
  async function triggerAudit() {
    "use server";
    try {
      await fetch(
        `${process.env.NEXT_PUBLIC_APP_URL ?? "http://localhost:3000"}/api/admin/trigger-audit`,
        { method: "POST" },
      );
    } catch { /* silent */ }
    revalidatePath("/(dashboard)");
  }

  // ── Render ────────────────────────────────────────────────────────────────
  return (
    <div className="max-w-7xl mx-auto space-y-8 animate-in fade-in duration-700">

      {/* ── HEADER ──────────────────────────────────────────────────────── */}
      <div className="flex justify-between items-start border-b border-[#003478]/15 pb-6">
        <div>
          <div className="flex items-center gap-3 mb-1">
            <div className="w-8 h-8 bg-[#003478] rounded-lg flex items-center justify-center">
              <Shield className="text-white" size={16} />
            </div>
            <h1 className="text-2xl font-black tracking-tight text-[#003478]">
              NPCI Identity Guard
            </h1>
          </div>
          <p className="text-sm text-[#0066b3]/70 ml-11">
            <span className="text-[#f7941d] font-bold">SOC Command Center</span>
            {" "}— Fraud Detection Engine Active
          </p>
          <p className="text-[10px] text-[#003478]/40 ml-11 mt-1 uppercase tracking-widest">
            Payment &amp; Settlement Systems Act, 2007 · RBI Regulated
          </p>
        </div>

        <div className="flex items-center gap-3">
          <form action={triggerAudit}>
            <button
              type="submit"
              className="flex items-center gap-2 bg-[#003478] text-white px-4 py-2 rounded-lg text-xs font-bold hover:bg-[#002560] transition-all shadow-md group"
            >
              <RefreshCw className="w-3 h-3 group-hover:rotate-180 transition-transform duration-500" />
              Run AI Behavioral Audit
            </button>
          </form>
          <Badge className="px-3 py-1 uppercase font-bold tracking-tighter bg-[#f7941d] text-white border-none shadow-md animate-pulse text-[10px]">
            Response Engine Live
          </Badge>
        </div>
      </div>

      {/* ── SECTION 1: SYSTEM OVERVIEW ──────────────────────────────────── */}
      <section>
        <h2 className="text-[10px] font-bold text-[#003478]/40 uppercase tracking-widest mb-4">
          System Overview
        </h2>

        {/* Stats strip */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
          <StatCard
            icon={<Users size={18} className="text-[#003478]" />}
            bg="bg-[#003478]/10"
            label="Monitored Users"
            value={users.length}
            valueColor="text-[#003478]"
          />
          <StatCard
            icon={<AlertCircle size={18} className="text-red-600" />}
            bg="bg-red-50"
            label="Active Alerts"
            value={totalActiveAlerts}
            valueColor="text-red-600"
          />
          <StatCard
            icon={<Zap size={18} className="text-[#f7941d]" />}
            bg="bg-[#f7941d]/10"
            label="Flagged Users"
            value={flaggedCount}
            valueColor="text-[#f7941d]"
          />
          <div className="bg-white rounded-xl border border-[#003478]/10 p-4 shadow-sm flex items-center gap-3">
            <div className="w-10 h-10 bg-[#003478]/5 rounded-lg flex items-center justify-center">
              <ShieldCheck size={18} className="text-[#003478]" />
            </div>
            <div>
              <p className="text-[10px] text-[#003478]/50 uppercase tracking-wider font-semibold">
                System Risk
              </p>
              <Badge className={`text-xs font-black mt-0.5 border-none ${riskLevelBadgeStyle(systemRiskLevel)}`}>
                {systemRiskLevel}
              </Badge>
            </div>
          </div>
        </div>

        {/* Severity breakdown + live alert feed */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {/* Severity breakdown */}
          <Card className="border-[#003478]/10 shadow-sm">
            <CardHeader className="pb-3">
              <CardTitle className="text-xs font-bold text-[#003478]/60 uppercase tracking-wider">
                Alerts by Severity
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              {(["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const).map((sev) => (
                <div key={sev} className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <div
                      className={`w-2 h-2 rounded-full ${
                        sev === "CRITICAL" ? "bg-red-500" :
                        sev === "HIGH"     ? "bg-orange-500" :
                        sev === "MEDIUM"   ? "bg-yellow-500" :
                                             "bg-emerald-500"
                      }`}
                    />
                    <span className="text-xs text-[#003478]/70 font-medium">{sev}</span>
                  </div>
                  <span className="text-sm font-black text-[#003478]">
                    {countBySeverity[sev] ?? 0}
                  </span>
                </div>
              ))}
            </CardContent>
          </Card>

          {/* Live alert feed */}
          <Card className="md:col-span-2 border-[#003478]/10 shadow-sm">
            <CardHeader className="pb-3">
              <div className="flex items-center justify-between">
                <CardTitle className="text-xs font-bold text-[#003478]/60 uppercase tracking-wider flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full bg-[#f7941d] animate-pulse" />
                  Live Alert Feed
                </CardTitle>
                <span className="text-[9px] text-[#003478]/30 font-mono">
                  Last {recentAlerts.length} active
                </span>
              </div>
            </CardHeader>
            <CardContent className="p-0">
              {recentAlerts.length === 0 ? (
                <p className="text-center text-xs text-[#003478]/30 italic py-6">
                  No active alerts.
                </p>
              ) : (
                <div className="divide-y divide-[#003478]/5 max-h-56 overflow-y-auto">
                  {recentAlerts.map((alert) => (
                    <div
                      key={alert.id}
                      className="flex items-center justify-between px-5 py-2.5 hover:bg-[#e8f1fb]/30 transition-colors"
                    >
                      <div className="flex items-center gap-2 min-w-0">
                        <div
                          className={`w-1.5 h-1.5 rounded-full shrink-0 ${
                            alert.severity === "CRITICAL" ? "bg-red-500 animate-pulse" :
                            alert.severity === "HIGH"     ? "bg-orange-500" :
                            alert.severity === "MEDIUM"   ? "bg-yellow-500" :
                                                            "bg-emerald-500"
                          }`}
                        />
                        <span className="text-xs font-semibold text-[#003478] truncate">
                          {alert.user.name ?? alert.user.email}
                        </span>
                      </div>
                      <div className="flex items-center gap-3 shrink-0 ml-2">
                        <Badge className={`text-[9px] font-bold border ${severityColor(alert.severity)}`}>
                          {alert.severity}
                        </Badge>
                        <span className="text-[10px] text-[#003478]/30 font-mono flex items-center gap-1">
                          <Clock size={9} />
                          {timeAgo(new Date(alert.createdAt))}
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      </section>

      {/* ── SECTION 2: ANOMALY ALERTS PANEL ─────────────────────────────── */}
      <section>
        <h2 className="text-[10px] font-bold text-[#003478]/40 uppercase tracking-widest mb-4">
          Anomaly Alerts
          <span className="ml-2 text-[#003478]/20 normal-case font-normal">
            — auto-refreshes every 60 s
          </span>
        </h2>
        <AlertsPanel />
      </section>

      {/* ── SECTION 3 + 4: USER DRILLDOWN & INCIDENT RESPONSE ───────────── */}
      <section>
        <h2 className="text-[10px] font-bold text-[#003478]/40 uppercase tracking-widest mb-4">
          Identity Risk Console
          <span className="ml-2 text-[#003478]/20 normal-case font-normal">
            — click Deep Audit to open drilldown &amp; incident response
          </span>
        </h2>

        <Card className="shadow-md border-[#003478]/10 overflow-hidden">
          <CardHeader className="bg-[#003478] px-6 py-4">
            <div className="flex items-center justify-between">
              <CardTitle className="text-white text-sm font-bold uppercase tracking-wider flex items-center gap-2">
                <Activity size={14} className="text-[#f7941d]" />
                User Behavioral Risk Table
              </CardTitle>
              <span className="text-[10px] text-blue-200/50 uppercase tracking-widest">
                {users.length} identities monitored
              </span>
            </div>
          </CardHeader>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow className="bg-[#e8f1fb]/60 border-b border-[#003478]/10">
                  <TableHead className="text-[#003478] font-bold text-xs uppercase tracking-wider w-[260px]">
                    Identity
                  </TableHead>
                  <TableHead className="text-[#003478] font-bold text-xs uppercase tracking-wider">
                    Risk Status
                  </TableHead>
                  <TableHead className="text-[#003478] font-bold text-xs uppercase tracking-wider">
                    30-Day Trend
                  </TableHead>
                  <TableHead className="text-[#003478] font-bold text-xs uppercase tracking-wider">
                    Last Analyzed
                  </TableHead>
                  <TableHead className="text-right text-[#003478] font-bold text-xs uppercase tracking-wider">
                    Action
                  </TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {users.map((user) => (
                  <TableRow
                    key={user.id}
                    className={`hover:bg-[#e8f1fb]/40 transition-colors border-b border-[#003478]/5 ${
                      user.status === "LOCKED" ? "opacity-60 bg-[#e8f1fb]/20" : ""
                    }`}
                  >
                    {/* Identity */}
                    <TableCell>
                      <div className="flex flex-col">
                        <div className="flex items-center gap-2">
                          <span className="font-semibold text-[#003478] text-sm">
                            {user.name}
                          </span>
                          {user.status === "LOCKED" && (
                            <Lock className="w-3 h-3 text-red-500" />
                          )}
                        </div>
                        <span className="text-xs text-[#0066b3]/60 font-mono">
                          {user.email}
                        </span>
                      </div>
                    </TableCell>

                    {/* Risk status */}
                    <TableCell>
                      <div className="flex items-center gap-2">
                        {user.isFlagged && (
                          <span className="flex items-center gap-1 text-[9px] bg-[#f7941d] text-white font-black px-1.5 py-0.5 rounded animate-pulse">
                            <Zap className="w-2.5 h-2.5" /> ANOMALY
                          </span>
                        )}
                        <Badge
                          className={`text-xs font-bold border ${
                            user.riskScore >= 90 ? "bg-red-50 text-red-700 border-red-200" :
                            user.riskScore >= 70 ? "bg-orange-50 text-orange-700 border-orange-200" :
                            user.riskScore >= 40 ? "bg-yellow-50 text-yellow-700 border-yellow-200" :
                                                   "bg-emerald-50 text-emerald-700 border-emerald-200"
                          }`}
                        >
                          {user.riskScore}/100
                        </Badge>
                      </div>
                    </TableCell>

                    {/* Sparkline */}
                    <TableCell>
                      <div className="flex gap-0.5 items-end h-5">
                        {user.snapshots.map((s, i) => (
                          <div
                            key={i}
                            className="w-1.5 rounded-sm transition-all"
                            style={{
                              height: `${Math.max(Math.round((s.riskScore / 100) * 20), 2)}px`,
                              backgroundColor: s.riskScore >= 70 ? "#f7941d" :
                                               s.riskScore >= 40 ? "#6baed6" : "#003478",
                              opacity: 0.6 + i * 0.06,
                            }}
                          />
                        ))}
                      </div>
                    </TableCell>

                    {/* Last analyzed */}
                    <TableCell>
                      <span className="text-[11px] text-[#003478]/40 font-mono">
                        {user.lastAnalyzed
                          ? timeAgo(new Date(user.lastAnalyzed))
                          : "Never"}
                      </span>
                    </TableCell>

                    {/* Drilldown trigger (UserDrilldownSheet) */}
                    <TableCell className="text-right">
                      <UserDrilldownSheet user={user} />
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      </section>
    </div>
  );
}

// ── Reusable stat card ─────────────────────────────────────────────────────────

function StatCard({
  icon, bg, label, value, valueColor,
}: {
  icon: React.ReactNode;
  bg: string;
  label: string;
  value: number;
  valueColor: string;
}) {
  return (
    <div className="bg-white rounded-xl border border-[#003478]/10 p-4 shadow-sm flex items-center gap-3">
      <div className={`w-10 h-10 ${bg} rounded-lg flex items-center justify-center`}>
        {icon}
      </div>
      <div>
        <p className="text-[10px] text-[#003478]/50 uppercase tracking-wider font-semibold">
          {label}
        </p>
        <p className={`text-xl font-black ${valueColor}`}>{value}</p>
      </div>
    </div>
  );
}
