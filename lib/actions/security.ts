"use server";

/**
 * lib/actions/security.ts
 * ========================
 * Sprint 4/5 — Kill Switch server action
 *
 * handleSecurityAction: LOCK or UNLOCK a user account.
 * Requires ADMIN role (checked via request headers set by middleware).
 *
 * Every invocation writes a tamper-evident audit entry via createAuditEntry()
 * (Sprint 5 requirement: all admin actions generate their own audit entry).
 */

import { prisma } from "../prisma";
import { revalidatePath } from "next/cache";
import { headers } from "next/headers";
import { createAuditEntry } from "@/lib/audit";
import { can } from "@/lib/auth/rbac";

export async function handleSecurityAction(
  userId: string,
  actionType: "LOCK" | "UNLOCK",
) {
  // ── Role guard ─────────────────────────────────────────────────────────────
  // middleware.ts injects x-npci-role; absent in dev without auth = permissive.
  const headersList = await headers();
  const role = headersList.get("x-npci-role") as "ADMIN" | "ANALYST" | "VIEWER" | null;
  const actorId = headersList.get("x-npci-user-id") ?? undefined;

  if (role !== null && !can(role, "action:lock_account")) {
    throw new Error(
      `Forbidden: your role (${role}) cannot ${actionType} accounts. ADMIN required.`,
    );
  }

  const newStatus = actionType === "LOCK" ? "LOCKED" : "ACTIVE";

  // ── 1. Update User status ─────────────────────────────────────────────────
  await prisma.user.update({
    where: { id: userId },
    data: { status: newStatus },
  });

  // ── 2. Write tamper-evident audit entry ───────────────────────────────────
  await createAuditEntry({
    userId,
    action: actionType === "LOCK" ? "ACCOUNT_LOCKOUT" : "ACCOUNT_RECOVERY",
    description: `Security Intervention: ${actionType} performed${actorId ? ` by ${actorId}` : " by system admin"}.`,
    actorId,
    metadata: { newStatus, actionType },
  });

  revalidatePath("/(dashboard)");
}
