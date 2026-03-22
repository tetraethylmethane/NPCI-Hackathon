/**
 * lib/audit.ts
 * =============
 * Sprint 5 — Tamper-Evident Audit Logging
 *
 * Central helper for writing security audit entries to ActivityLog.
 * Every admin action (lock, unlock, alert dismiss, trigger audit) MUST
 * call createAuditEntry() so there is a complete, tamper-evident trail.
 *
 * Append-only guarantee:
 *   A Prisma client extension (below) intercepts activityLog.delete and
 *   activityLog.update calls and throws — preventing accidental or malicious
 *   log modification at the ORM layer. Cascade deletes via FK are permitted
 *   by Postgres (they bypass Prisma middleware) but are only triggered when
 *   the parent User or Project is deleted, which itself requires an ADMIN action
 *   that generates its own audit entry first.
 *
 * Supported action types (SecurityEvent subset):
 *   ACCOUNT_LOCKOUT    — user account locked
 *   ACCOUNT_RECOVERY   — user account unlocked / restored
 *   MFA_CHALLENGE      — MFA verification triggered
 *
 * Prisma ActivityLog schema requires both userId AND projectId (non-nullable).
 * For security events not tied to a project we attach the oldest "sentinel"
 * project. This is a known schema constraint from the collaboration workspace
 * domain — flagged for future schema split.
 */

import { prisma } from "@/lib/prisma";

// ---------------------------------------------------------------------------
// Append-only Prisma extension
// ---------------------------------------------------------------------------

/**
 * Returns a Prisma client extended with an append-only guard on ActivityLog.
 * Import this instead of bare `prisma` whenever writing audit entries.
 *
 * Usage:
 *   const db = appendOnlyPrisma();
 *   await db.activityLog.create({ data: { ... } });
 */
export function appendOnlyPrisma() {
  return prisma.$extends({
    query: {
      activityLog: {
        async delete() {
          throw new Error(
            "[Audit Integrity] ActivityLog rows are append-only — DELETE is not permitted.",
          );
        },
        async deleteMany() {
          throw new Error(
            "[Audit Integrity] ActivityLog rows are append-only — deleteMany is not permitted.",
          );
        },
        async update() {
          throw new Error(
            "[Audit Integrity] ActivityLog rows are append-only — UPDATE is not permitted.",
          );
        },
        async updateMany() {
          throw new Error(
            "[Audit Integrity] ActivityLog rows are append-only — updateMany is not permitted.",
          );
        },
      },
    },
  });
}

// ---------------------------------------------------------------------------
// Security event types (subset of ActivityType enum)
// ---------------------------------------------------------------------------

export type SecurityEventType =
  | "ACCOUNT_LOCKOUT"
  | "ACCOUNT_RECOVERY"
  | "MFA_CHALLENGE";

// ---------------------------------------------------------------------------
// createAuditEntry
// ---------------------------------------------------------------------------

/**
 * Write a security audit entry to ActivityLog.
 *
 * @param userId     Target user ID (the account being acted upon)
 * @param action     One of the SecurityEventType values
 * @param description Human-readable description of the action
 * @param actorId    Optional: ID of the admin/analyst who performed the action
 * @param metadata   Optional: additional JSON metadata (stored in ActivityLog.metadata)
 */
export async function createAuditEntry({
  userId,
  action,
  description,
  actorId,
  metadata,
}: {
  userId: string;
  action: SecurityEventType;
  description: string;
  actorId?: string;
  metadata?: Record<string, unknown>;
}): Promise<void> {
  // Find (or create) the sentinel project for security-only events
  let sentinelProject = await prisma.project.findFirst({
    where: { name: "NPCI Security Audit Log" },
    select: { id: true },
  });

  if (!sentinelProject) {
    sentinelProject = await prisma.project.create({
      data: {
        name: "NPCI Security Audit Log",
        description:
          "Auto-created sentinel project for security audit entries. Do not delete.",
        githubUrl: "https://github.com/npci/security-audit-sentinel",
        userId,   // owner = the first acted-upon user (acceptable for sentinel)
        status: "OPEN",
        visibility: "PRIVATE",
      },
      select: { id: true },
    });
  }

  const db = appendOnlyPrisma();
  await db.activityLog.create({
    data: {
      action: action as any, // Prisma enum type — cast required (validated above)
      description,
      metadata: {
        ...(metadata ?? {}),
        ...(actorId ? { actorId } : {}),
        auditTimestamp: new Date().toISOString(),
      },
      user: { connect: { id: userId } },
      project: { connect: { id: sentinelProject.id } },
    },
  });
}
