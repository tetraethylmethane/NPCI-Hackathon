export const dynamic = "force-dynamic";

import { prisma } from "@/lib/prisma";

// 1. The Logic for the Badges
const getRiskStatus = (score: number) => {
  if (score >= 80) return { label: "CRITICAL", color: "bg-red-600 text-white animate-pulse" };
  if (score >= 40) return { label: "WARNING", color: "bg-orange-500 text-white" };
  return { label: "LOW", color: "bg-green-500 text-white" };
};

export default async function AdminUserPage() {
  // 2. FETCH THE USERS FROM NEON
  const users = await prisma.user.findMany({
    orderBy: { riskScore: 'desc' }
  }).catch(() => []);

  return (
    <div className="p-8">
      <h1 className="text-2xl font-bold mb-6">Xcelit Security Overview</h1>
      
      <table className="min-w-full bg-white border rounded-lg">
        <thead>
          <tr className="bg-gray-100 border-b">
            <th className="px-6 py-3 text-left">User Name</th>
            <th className="px-6 py-3 text-left">Behavioral Risk</th>
            <th className="px-6 py-3 text-left">Daily Actions</th>
          </tr>
        </thead>
        <tbody>
          {/* 3. THE LOOP: This is where 'user' is defined */}
          {users.map((user) => (
            <tr key={user.id} className="border-b hover:bg-gray-50">
              <td className="px-6 py-4 font-medium">{user.name || user.email}</td>
              <td className="px-6 py-4">
                <span className={`px-2 py-1 rounded-md text-xs font-bold ${getRiskStatus(user.riskScore || 0).color}`}>
                  {getRiskStatus(user.riskScore || 0).label} ({user.riskScore || 0})
                </span>
              </td>
              <td className="px-6 py-4 text-gray-600">
                {user.avgActionsDay || 0} actions/day
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}