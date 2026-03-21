/**
 * POST /api/ml/analyze
 * =====================
 * Next.js proxy to the FastAPI /analyze/user/{userId} endpoint.
 *
 * Flow:
 *  1. Receive { userId } from dashboard or internal caller.
 *  2. Compute Layer 1 Z-Score locally (fast — no external call needed).
 *  3. Forward userId + zScore to FastAPI which runs Layers 2 + 3.
 *  4. FastAPI writes RiskSnapshot + Alert to Postgres and returns result.
 *  5. Return the full MLAnalysisResult to the caller.
 *
 * Falls back to local Z-Score analysis if FastAPI is unreachable.
 */

import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { vectorizeUserBehavior } from "@/lib/analysis";
import { mean, standardDeviation, zScore } from "simple-statistics";
import { ML_SERVICE_URL, Z_THRESHOLD, WINDOW_DAYS } from "@/lib/env";

export async function POST(req: NextRequest) {
  const body = await req.json().catch(() => ({}));
  const { userId } = body as { userId?: string };

  if (!userId) {
    return NextResponse.json({ error: "userId is required" }, { status: 400 });
  }

  // Compute Layer 1 Z-Score for this user to pass to FastAPI
  const zScoreValue = await _computeZScore(userId);

  // Call FastAPI with the pre-computed Z-Score
  try {
    const mlRes = await fetch(`${ML_SERVICE_URL}/analyze/user/${userId}`, {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ z_score: zScoreValue }),
      signal:  AbortSignal.timeout(10_000),
    });

    if (mlRes.ok) {
      const data = await mlRes.json();
      return NextResponse.json({ success: true, source: "ml-service", ...data });
    }

    const errText = await mlRes.text().catch(() => "");
    console.warn(`[ML Analyze] FastAPI returned ${mlRes.status}: ${errText}`);
  } catch (err) {
    console.warn("[ML Analyze] FastAPI unreachable, falling back to Z-Score:", err);
  }

  // Fallback: run local Z-Score via vectorizeUserBehavior
  try {
    await vectorizeUserBehavior(userId);
    return NextResponse.json({
      success: true,
      source:  "zscore-fallback",
      user_id: userId,
      message: "ML service unavailable — Z-Score fallback used.",
    });
  } catch (fallbackErr) {
    return NextResponse.json(
      { success: false, error: String(fallbackErr) },
      { status: 500 }
    );
  }
}

// ── Layer 1: compute Z-Score from Postgres snapshot history ──────────────────

async function _computeZScore(userId: string): Promise<number | null> {
  const cutoff = new Date(Date.now() - WINDOW_DAYS * 24 * 60 * 60 * 1000);

  const [history, logs] = await Promise.all([
    prisma.userSnapshot.findMany({
      where:   { userId },
      orderBy: { createdAt: "desc" },
      take:    WINDOW_DAYS,
      select:  { riskScore: true },
    }),
    prisma.activityLog.findMany({
      where:   { userId, createdAt: { gte: cutoff } },
      select:  { action: true },
    }),
  ]);

  if (logs.length === 0 || history.length < 3) return null;

  const currentRisk =
    logs.length * 1 +
    logs.filter(l => String(l.action).includes("DELETE")).length * 25;

  const scores = history.map(h => h.riskScore);
  const avg    = mean(scores);
  const std    = standardDeviation(scores);

  if (std === 0) return null;
  return zScore(currentRisk, avg, std);
}
