import { Search, Bell, Shield, Activity, Building2 } from "lucide-react";
import { Input } from "@/components/ui/input";

export default function DashboardLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex h-screen bg-[#e8f1fb] text-[#1a2a4a] font-sans">
      {/* NPCI Sidebar — Navy Blue */}
      <aside className="w-72 bg-[#003478] flex flex-col hidden md:flex shadow-xl">
        {/* NPCI Logo / Branding */}
        <div className="px-6 py-5 border-b border-white/10">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-[#f7941d] rounded-lg flex items-center justify-center shrink-0 shadow-md">
              <Shield className="text-white" size={20} />
            </div>
            <div className="leading-tight">
              <div className="font-black text-white text-base tracking-tight">NPCI</div>
              <div className="text-[10px] text-blue-200 font-medium tracking-widest uppercase">Identity Guard</div>
            </div>
          </div>
          <p className="text-[9px] text-blue-300/70 mt-3 leading-relaxed uppercase tracking-wider">
            National Payments Corporation of India
          </p>
        </div>

        {/* Navigation */}
        <nav className="flex-1 p-4 space-y-1">
          <p className="text-[9px] text-blue-300/50 uppercase tracking-widest px-3 pb-2 pt-2 font-semibold">
            Command Center
          </p>
          <button className="flex items-center gap-3 w-full text-left px-3 py-2.5 text-sm font-semibold bg-[#f7941d] text-white rounded-lg shadow-md">
            <Activity size={15} /> Risk Overview
          </button>
          <button className="flex items-center gap-3 w-full text-left px-3 py-2.5 text-sm font-medium text-blue-200 hover:bg-white/10 rounded-lg transition-colors">
            <Shield size={15} /> Identity Monitor
          </button>
          <button className="flex items-center gap-3 w-full text-left px-3 py-2.5 text-sm font-medium text-blue-200 hover:bg-white/10 rounded-lg transition-colors">
            <Building2 size={15} /> Institutional Access
          </button>
        </nav>

        {/* Footer — RBI / IBA badge */}
        <div className="px-5 py-4 border-t border-white/10">
          <div className="bg-white/5 rounded-lg p-3 text-center">
            <p className="text-[8px] text-blue-300/60 uppercase tracking-widest">An initiative of</p>
            <p className="text-[10px] text-blue-100 font-bold mt-0.5">RBI &amp; IBA</p>
            <p className="text-[8px] text-blue-300/50 mt-0.5">Payment &amp; Settlement Systems Act, 2007</p>
          </div>
        </div>
      </aside>

      {/* Main Content */}
      <main className="flex-1 flex flex-col overflow-hidden">
        {/* Header */}
        <header className="h-16 border-b border-[#003478]/15 bg-white flex items-center justify-between px-8 shadow-sm">
          <div className="flex items-center gap-4">
            {/* Mobile logo */}
            <div className="md:hidden flex items-center gap-2">
              <div className="w-8 h-8 bg-[#003478] rounded-lg flex items-center justify-center">
                <Shield className="text-white" size={16} />
              </div>
              <span className="font-black text-[#003478] text-sm">NPCI</span>
            </div>
            <div className="relative w-80 flex items-center">
              <Search className="absolute left-3 text-[#0066b3]/60" size={15} />
              <Input
                placeholder="Search transactions, users... (⌘K)"
                className="pl-9 bg-[#e8f1fb]/70 border-[#003478]/15 rounded-full h-9 text-sm placeholder:text-[#0066b3]/50 focus:border-[#f7941d] focus:ring-[#f7941d]/20"
              />
            </div>
          </div>

          <div className="flex items-center gap-4">
            <div className="flex items-center gap-2">
              <div className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
              <span className="text-xs font-semibold text-emerald-600 uppercase tracking-wider">Systems Operational</span>
            </div>
            <button className="relative p-2 rounded-lg hover:bg-[#e8f1fb] transition-colors">
              <Bell size={18} className="text-[#003478]" />
              <span className="absolute top-1.5 right-1.5 w-1.5 h-1.5 bg-[#f7941d] rounded-full" />
            </button>
            <div className="w-8 h-8 rounded-full bg-[#003478] flex items-center justify-center text-white text-xs font-bold">
              AD
            </div>
          </div>
        </header>

        <div className="flex-1 overflow-y-auto p-8">
          {children}
        </div>
      </main>
    </div>
  );
}
