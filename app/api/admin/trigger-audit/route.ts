/**
 * POST /api/admin/trigger-audit
 * ================================
 * Manual audit trigger from the dashboard.
 *
 * Sprint 2 behaviour:
 *  1. Try FastAPI POST /analyze/batch — runs all 3 detection layers for all users,
 *     writes RiskSnapshot + Alert rows to Postgres, returns immediately (background job).
 *  2. If FastAPI is unreachable, fall back to local Z-Score via vectorizeUserBehavior
 *     for each user (Sprint 1 / Layer 1 only).
 */

import { NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { vectorizeUserBehavior } from "@/lib/analysis";
import { ML_SERVICE_URL } from "@/lib/env";

export async function POST() {
  console.log("⚡ Manual Audit Triggered via Dashboard…");

  // ── Attempt FastAPI batch ──────────────────────────────────────────────────
  try {
    const mlRes = await fetch(`${ML_SERVICE_URL}/analyze/batch`, {
      method: "POST",
      signal: AbortSignal.timeout(5_000),
    });

    if (mlRes.ok) {
      const data = await mlRes.json();
      console.log("✅ FastAPI batch analysis queued:", data.message);
      return NextResponse.json({
        success: true,
        source:  "ml-service",
        message: "3-layer batch analysis queued. Results will appear in the dashboard shortly.",
      });
    }

    console.warn(`FastAPI returned ${mlRes.status} — falling back to Z-Score.`);
  } catch (err) {
    console.warn("FastAPI unreachable — falling back to Z-Score analysis:", err);
  }

  // ── Fallback: local Z-Score ────────────────────────────────────────────────
  try {
    const users = await prisma.user.findMany({ select: { id: true } });
    let analyzed = 0;
    let errors   = 0;

    for (const user of users) {
      try {
        await vectorizeUserBehavior(user.id);
        analyzed++;
      } catch (e) {
        errors++;
        console.error(`Z-Score failed for user ${user.id}:`, e);
      }
    }

    return NextResponse.json({
      success:  true,
      source:   "zscore-fallback",
      message:  `Z-Score audit complete (ML service unavailable). ${analyzed} users analyzed, ${errors} errors.`,
      analyzed,
      errors,
    });
  } catch (error) {
    return NextResponse.json(
      { success: false, error: "Audit failed entirely." },
      { status: 500 }
    );
  }
}
