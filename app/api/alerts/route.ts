/**
 * GET /api/alerts
 * ===============
 * Returns alert rows with joined user data.
 *
 * Query params:
 *   severity  — CRITICAL | HIGH | MEDIUM | LOW  (omit = all)
 *   status    — OPEN | ASSIGNED | ACKNOWLEDGED | ALL  (default = active)
 *   limit     — max rows (default 50, max 100)
 */

import { NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";

export async function GET(req: Request) {
  const { searchParams } = new URL(req.url);
  const severity = searchParams.get("severity");
  const statusParam = searchParams.get("status") ?? "active";
  const limit = Math.min(parseInt(searchParams.get("limit") ?? "50", 10), 100);

  const statusFilter =
    statusParam === "ALL"
      ? undefined
      : { in: ["OPEN", "ASSIGNED", "ACKNOWLEDGED"] as const };

  const alerts = await prisma.alert.findMany({
    where: {
      ...(severity ? { severity: severity as any } : {}),
      ...(statusFilter ? { status: statusFilter } : {}),
    },
    orderBy: { createdAt: "desc" },
    take: limit,
    include: {
      user: {
        select: {
          id: true,
          name: true,
          email: true,
          status: true,
          lastLocation: true,
        },
      },
    },
  });

  return NextResponse.json({ alerts });
}
