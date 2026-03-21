/**
 * GET /api/admin/audit-log
 * =========================
 * Sprint 5 — Admin-Only Audit Trail
 *
 * Returns security audit entries (ACCOUNT_LOCKOUT, ACCOUNT_RECOVERY,
 * MFA_CHALLENGE) from ActivityLog, newest first.
 *
 * Access: ADMIN role only (enforced by middleware + explicit header check).
 *
 * Query params:
 *   limit   — max rows to return (default 100, max 500)
 *   userId  — optional filter to a specific user
 */

import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";

const SECURITY_ACTIONS = [
  "ACCOUNT_LOCKOUT",
  "ACCOUNT_RECOVERY",
  "MFA_CHALLENGE",
];

export async function GET(request: NextRequest) {
  // ── Role guard (belt-and-suspenders: middleware already checked, but verify again) ──
  const role = request.headers.get("x-npci-role");
  if (role !== "ADMIN") {
    return NextResponse.json(
      { error: "Forbidden: audit log requires ADMIN role." },
      { status: 403 },
    );
  }

  const { searchParams } = request.nextUrl;
  const limitParam = parseInt(searchParams.get("limit") ?? "100", 10);
  const limit = Math.min(Math.max(limitParam, 1), 500);
  const userId = searchParams.get("userId") ?? undefined;

  const entries = await prisma.activityLog.findMany({
    where: {
      action: { in: SECURITY_ACTIONS as any[] },
      ...(userId ? { userId } : {}),
    },
    orderBy: { createdAt: "desc" },
    take: limit,
    select: {
      id: true,
      action: true,
      description: true,
      metadata: true,
      createdAt: true,
      user: {
        select: { id: true, name: true, email: true, status: true, securityRole: true },
      },
    },
  });

  return NextResponse.json({
    total: entries.length,
    entries,
  });
}
