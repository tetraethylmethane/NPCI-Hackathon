/**
 * GET /api/risk-summary
 * =====================
 * Returns system-wide risk statistics and the last 10 active alerts.
 * Used by the System Overview Panel and polled every 60 s by the dashboard.
 */

import { NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";

export async function GET() {
  try {
  const [totalUsers, flaggedUsers, alertGroups, recentAlerts] = await Promise.all([
    prisma.user.count(),
    prisma.user.count({ where: { isFlagged: true } }),
    prisma.alert.groupBy({
      by: ["severity"],
      where: { status: { in: ["OPEN", "ASSIGNED", "ACKNOWLEDGED"] } },
      _count: { id: true },
    }),
    prisma.alert.findMany({
      where: { status: { in: ["OPEN", "ASSIGNED", "ACKNOWLEDGED"] } },
      orderBy: { createdAt: "desc" },
      take: 10,
      include: {
        user: { select: { name: true, email: true } },
      },
    }),
  ]);

  const countBySeverity: Record<string, number> = {
    CRITICAL: 0,
    HIGH: 0,
    MEDIUM: 0,
    LOW: 0,
  };
  for (const g of alertGroups) {
    countBySeverity[g.severity] = g._count.id;
  }

  const totalActiveAlerts = alertGroups.reduce((s, g) => s + g._count.id, 0);

  let systemRiskLevel = "LOW";
  if (countBySeverity.CRITICAL > 0) systemRiskLevel = "CRITICAL";
  else if (countBySeverity.HIGH > 0) systemRiskLevel = "HIGH";
  else if (countBySeverity.MEDIUM > 0) systemRiskLevel = "MEDIUM";

  return NextResponse.json({
    totalUsers,
    flaggedUsers,
    totalActiveAlerts,
    systemRiskLevel,
    countBySeverity,
    recentAlerts,
  });
  } catch {
    return NextResponse.json({
      totalUsers: 0, flaggedUsers: 0, totalActiveAlerts: 0,
      systemRiskLevel: "LOW", countBySeverity: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 },
      recentAlerts: [],
    });
  }
}
