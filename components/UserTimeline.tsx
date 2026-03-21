import { prisma } from "@/lib/prisma";

export default async function UserTimeline({ userId }: { userId: string }) {
  // Fetch the 5 most recent actions for this user
  const logs = await prisma.activityLog.findMany({
    where: { userId },
    orderBy: { createdAt: 'desc' },
    take: 5,
  });

  return (
    <div className="mt-4 border-l-2 border-slate-200 ml-4 pl-4 space-y-4">
      <h4 className="text-xs font-bold text-slate-500 uppercase tracking-widest">
        Security Events
      </h4>
      {logs.length === 0 ? (
        <p className="text-xs text-slate-400 italic">No events found.</p>
      ) : (
        logs.map((log) => (
          <div key={log.id} className="relative">
            {/* The Status Dot */}
            <div className={`absolute -left-[21px] mt-1 w-3 h-3 rounded-full border-2 border-white ${
              log.action.includes('DELETE') ? 'bg-red-500' : 'bg-blue-400'
            }`} />
            
            <div className="text-sm">
              <span className="font-bold text-slate-800">{log.action}</span>
              <p className="text-slate-600 text-xs">{log.description}</p>
              <span className="text-[10px] text-slate-400">
                {new Date(log.createdAt).toLocaleTimeString()}
              </span>
            </div>
          </div>
        ))
      )}
    </div>
  );
}