/**
 * GET /api/users/[id]/snapshot
 * =============================
 * Lazy-loaded drilldown data for the User Behavior Drilldown panel.
 * Called when an analyst opens the detail Sheet for a user.
 *
 * Returns: user fields + last 30 UserSnapshots + last 30 RiskSnapshots
 *           + last 200 ActivityLogs (for the activity heatmap).
 */

import { NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";

export async function GET(
  _req: Request,
  { params }: { params: Promise<{ id: string }> },
) {
  const { id } = await params;

  try {
  const user = await prisma.user.findUnique({
    where: { id },
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
        take: 30,
        select: { id: true, riskScore: true, baseline: true, createdAt: true, vectorData: true },
      },
      riskSnapshots: {
        orderBy: { createdAt: "desc" },
        take: 30,
        select: {
          id: true,
          threatScore: true,
          ifScore: true,
          lstmScore: true,
          zScore: true,
          severity: true,
          anomalyFlags: true,
          contributingFeatures: true,
          featureVector: true,
          createdAt: true,
        },
      },
      activityLogs: {
        orderBy: { createdAt: "desc" },
        take: 200,
        select: { id: true, action: true, description: true, createdAt: true },
      },
    },
  });

  if (!user) {
    return NextResponse.json({ error: "User not found" }, { status: 404 });
  }

  return NextResponse.json({ user });
  } catch {
    return NextResponse.json({ error: "Database unavailable" }, { status: 503 });
  }
}
