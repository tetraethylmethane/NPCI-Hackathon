import { prisma } from "@/lib/prisma";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
  SheetTrigger
} from "@/components/ui/sheet";
import { AlertCircle, ShieldCheck, Activity, RefreshCw, Zap, MapPin, Lock, Unlock, IndianRupee, Shield } from "lucide-react";
import { revalidatePath } from "next/cache";
import RiskTrendChart from "@/components/RiskTrendChart";
import { handleSecurityAction } from "@/lib/actions/security";

export default async function DashboardPage() {
  // 1. Fetch Users with history and snapshots
  const users = await prisma.user.findMany({
    orderBy: { riskScore: 'desc' },
    include: {
      activityLogs: {
        orderBy: { createdAt: 'desc' },
        take: 10
      },
      snapshots: {
        orderBy: { createdAt: 'desc' },
        take: 7
      }
    }
  });

  async function triggerAudit() {
    "use server";
    try {
      await fetch(`${process.env.NEXT_PUBLIC_APP_URL || 'http://localhost:3000'}/api/admin/trigger-audit`, {
        method: 'POST',
      });
      revalidatePath("/(dashboard)");
    } catch (e) {
      console.error("Audit trigger failed", e);
    }
  }

  return (
    <div className="max-w-7xl mx-auto space-y-8 animate-in fade-in duration-700">
      {/* HEADER */}
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
            <span className="text-[#f7941d] font-bold">Fraud Detection Command Center</span>
            {" "}— Behavioral Risk Engine Active
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

      {/* STATS STRIP */}
      <div className="grid grid-cols-3 gap-4">
        <div className="bg-white rounded-xl border border-[#003478]/10 p-4 shadow-sm flex items-center gap-3">
          <div className="w-10 h-10 bg-[#003478]/10 rounded-lg flex items-center justify-center">
            <Shield className="text-[#003478]" size={18} />
          </div>
          <div>
            <p className="text-[10px] text-[#003478]/50 uppercase tracking-wider font-semibold">Total Users</p>
            <p className="text-xl font-black text-[#003478]">{users.length}</p>
          </div>
        </div>
        <div className="bg-white rounded-xl border border-[#003478]/10 p-4 shadow-sm flex items-center gap-3">
          <div className="w-10 h-10 bg-red-50 rounded-lg flex items-center justify-center">
            <AlertCircle className="text-red-600" size={18} />
          </div>
          <div>
            <p className="text-[10px] text-[#003478]/50 uppercase tracking-wider font-semibold">High Risk</p>
            <p className="text-xl font-black text-red-600">{users.filter(u => u.riskScore > 75).length}</p>
          </div>
        </div>
        <div className="bg-white rounded-xl border border-[#003478]/10 p-4 shadow-sm flex items-center gap-3">
          <div className="w-10 h-10 bg-[#f7941d]/10 rounded-lg flex items-center justify-center">
            <Zap className="text-[#f7941d]" size={18} />
          </div>
          <div>
            <p className="text-[10px] text-[#003478]/50 uppercase tracking-wider font-semibold">Flagged</p>
            <p className="text-xl font-black text-[#f7941d]">{users.filter(u => u.isFlagged).length}</p>
          </div>
        </div>
      </div>

      {/* MAIN CONSOLE */}
      <Card className="shadow-md border-[#003478]/10 overflow-hidden bg-white">
        <CardHeader className="bg-[#003478] px-6 py-4">
          <div className="flex items-center justify-between">
            <CardTitle className="text-white text-sm font-bold uppercase tracking-wider flex items-center gap-2">
              <Activity size={14} className="text-[#f7941d]" />
              Identity Risk Console
            </CardTitle>
            <span className="text-[10px] text-blue-200/60 uppercase tracking-widest">
              Secured by NPCI Fraud Intelligence
            </span>
          </div>
        </CardHeader>
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow className="bg-[#e8f1fb]/60 border-b border-[#003478]/10">
                <TableHead className="w-[300px] text-[#003478] font-bold text-xs uppercase tracking-wider">Identity</TableHead>
                <TableHead className="text-[#003478] font-bold text-xs uppercase tracking-wider">Behavioral Risk Status</TableHead>
                <TableHead className="text-[#003478] font-bold text-xs uppercase tracking-wider">History</TableHead>
                <TableHead className="text-right text-[#003478] font-bold text-xs uppercase tracking-wider">Action</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {users.map((user) => (
                <TableRow
                  key={user.id}
                  className={`hover:bg-[#e8f1fb]/40 transition-colors group border-b border-[#003478]/5 ${user.status === 'LOCKED' ? 'opacity-60 bg-[#e8f1fb]/20' : ''}`}
                >
                  <TableCell>
                    <div className="flex flex-col">
                      <div className="flex items-center gap-2">
                        <span className="font-semibold text-[#003478]">{user.name}</span>
                        {user.status === 'LOCKED' && <Lock className="w-3 h-3 text-red-500" />}
                      </div>
                      <span className="text-xs text-[#0066b3]/60 font-mono">{user.email}</span>
                    </div>
                  </TableCell>

                  <TableCell>
                    <div className="flex items-center gap-3">
                      {user.isFlagged && (
                        <div className="flex items-center gap-1 text-[10px] bg-[#f7941d] text-white font-black px-1.5 py-0.5 rounded animate-pulse">
                          <Zap className="w-2.5 h-2.5" /> ANOMALY
                        </div>
                      )}
                      <Badge className={
                        user.riskScore > 75
                          ? "bg-red-50 text-red-700 border border-red-200 font-bold"
                          : "bg-emerald-50 text-emerald-700 border border-emerald-200 font-bold"
                      }>
                        {user.riskScore}/100
                      </Badge>
                    </div>
                  </TableCell>

                  <TableCell>
                    <div className="flex gap-0.5">
                      {user.snapshots.map((s, i) => (
                        <div key={i} className={`w-1 h-3 rounded-full ${s.riskScore > 50 ? 'bg-[#f7941d]' : 'bg-[#003478]/20'}`} />
                      ))}
                    </div>
                  </TableCell>

                  <TableCell className="text-right">
                    <Sheet>
                      <SheetTrigger asChild>
                        <button className="text-xs font-bold text-[#0066b3] hover:text-[#003478] underline underline-offset-4 transition-colors">
                          Deep Audit →
                        </button>
                      </SheetTrigger>
                      <SheetContent className="sm:max-w-xl bg-white border-l border-[#003478]/15 shadow-2xl overflow-y-auto">
                        <SheetHeader className="border-b border-[#003478]/10 pb-6">
                          <div className="flex justify-between items-center">
                            <div>
                              <div className="flex items-center gap-2 mb-1">
                                <div className="w-6 h-6 bg-[#003478] rounded flex items-center justify-center">
                                  <Shield className="text-white" size={12} />
                                </div>
                                <SheetTitle className="text-lg font-black text-[#003478]">Identity Evidence</SheetTitle>
                              </div>
                              <SheetDescription className="text-[10px] font-mono uppercase tracking-widest text-[#0066b3]/50">
                                Session ID: {user.id.slice(-8)}
                              </SheetDescription>
                            </div>

                            {/* KILL SWITCH */}
                            <form action={async () => {
                              "use server";
                              await handleSecurityAction(user.id, user.status === "ACTIVE" ? "LOCK" : "UNLOCK");
                            }}>
                              <button className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-bold transition-all shadow-sm ${
                                user.status === "ACTIVE"
                                  ? "bg-red-600 text-white hover:bg-red-700"
                                  : "bg-emerald-600 text-white hover:bg-emerald-700"
                              }`}>
                                {user.status === "ACTIVE" ? <Lock className="w-3 h-3" /> : <Unlock className="w-3 h-3" />}
                                {user.status === "ACTIVE" ? "KILL SESSION" : "RESTORE ACCESS"}
                              </button>
                            </form>
                          </div>
                        </SheetHeader>

                        {/* CHART */}
                        <div className="mt-6">
                          <RiskTrendChart snapshots={user.snapshots} />
                        </div>

                        {/* AI DIAGNOSTIC & GEO-TRACKING */}
                        <div className="mt-8 grid grid-cols-2 gap-4">
                           <div className="p-4 bg-[#003478] rounded-xl border border-[#002560] shadow-inner">
                              <h4 className="text-[10px] font-bold text-blue-300/70 uppercase flex items-center gap-2 mb-2">
                                <Zap className="w-3 h-3 text-[#f7941d]" /> AI Diagnostic
                              </h4>
                              <p className="text-xs text-blue-100 leading-relaxed">
                                {user.riskScore > 75
                                  ? "Critical behavioral drift. Unusually high volume of deletions detected outside standard baseline."
                                  : "Behavior stable. Current activity aligns with established identity clusters."}
                              </p>
                           </div>

                           <div className="p-4 bg-[#e8f1fb] rounded-xl border border-[#003478]/15">
                              <h4 className="text-[10px] font-bold text-[#003478]/50 uppercase flex items-center gap-2 mb-2">
                                <MapPin className="w-3 h-3 text-[#f7941d]" /> Access Geo
                              </h4>
                              <div className="flex items-center gap-2">
                                <span className="text-sm font-bold text-[#003478]">{user.lastLocation || "Mumbai, India"}</span>
                                {user.lastLocation && user.lastLocation !== "Mumbai, India" && (
                                  <Badge className="bg-red-100 text-red-600 text-[8px] h-4 border-red-200">ANOMALY</Badge>
                                )}
                              </div>
                           </div>
                        </div>

                        {/* ACTIVITY TRAIL */}
                        <div className="mt-10 relative">
                          <h3 className="text-xs font-bold text-[#003478]/40 uppercase mb-6 tracking-widest">
                            Recent Evidence Trail
                          </h3>
                          <div className="absolute left-[19px] top-10 bottom-0 w-[2px] bg-[#003478]/10" />
                          <div className="space-y-8">
                            {user.activityLogs.map((log) => (
                              <div key={log.id} className="relative flex items-start gap-6 group/item">
                                <div className={`mt-1 z-10 w-10 h-10 rounded-full flex items-center justify-center border-4 border-white shadow-sm shrink-0 transition-transform group-hover/item:scale-110 ${
                                  log.action.includes('DELETE') || log.action.includes('LOCK')
                                    ? 'bg-red-500'
                                    : 'bg-[#003478]'
                                }`}>
                                  <Activity className="w-4 h-4 text-white" />
                                </div>
                                <div className="space-y-1">
                                  <div className="flex items-center gap-2">
                                    <h4 className="font-bold text-sm text-[#003478]">{log.action}</h4>
                                    <span className="text-[10px] text-[#0066b3]/50 font-medium">
                                      {new Date(log.createdAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                                    </span>
                                  </div>
                                  <p className="text-xs text-[#003478]/60 leading-relaxed">{log.description}</p>
                                </div>
                              </div>
                            ))}
                          </div>
                        </div>
                      </SheetContent>
                    </Sheet>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}
