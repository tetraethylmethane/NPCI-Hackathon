/**
 * Sprint 2 — Layer 1: Statistical Baseline (Z-Score)
 * =====================================================
 * Extended from Sprint 3 baseline:
 *   - Rolling window: 30 snapshots (was 10)
 *   - Activity lookback: 30 days (was 24 h)
 *   - Anomaly threshold: Z > 2.5 (was 2.0) — reduces false positives
 *
 * Integration with FastAPI ML service (Layer 2 + 3):
 *   vectorizeUserBehavior() first attempts to call the FastAPI /analyze endpoint.
 *   If the service is unreachable or returns an error, it falls back gracefully
 *   to the Z-Score calculation and writes a RiskSnapshot with only zScore populated.
 *
 * RiskSnapshot is written on every run so the dashboard always has a fresh record.
 */

import { prisma } from "./prisma";
import { zScore, mean, standardDeviation } from "simple-statistics";
import { ML_SERVICE_URL, ALERT_THRESHOLD, Z_THRESHOLD, WINDOW_DAYS } from "./env";

// ─────────────────────────────────────────────────────────────────────────────
// Public entry point (called by cron, trigger-audit, and inline ingest)
// ─────────────────────────────────────────────────────────────────────────────

export async function vectorizeUserBehavior(userId: string): Promise<void> {
  const precomputedZ = await _computeZScore(userId);
  const mlResult = await _callMLService(userId, precomputedZ);

  if (mlResult) {
    await _persistMLResult(userId, mlResult);
    return;
  }

  // FastAPI unavailable — run Layer 1 (Z-Score) locally as fallback
  await _zScoreFallback(userId);
}

// ─────────────────────────────────────────────────────────────────────────────
// FastAPI integration
// ─────────────────────────────────────────────────────────────────────────────

async function _callMLService(userId: string, z_score: number | null): Promise<MLAnalysisResult | null> {
  try {
    const res = await fetch(`${ML_SERVICE_URL}/analyze/user/${userId}`, {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ z_score }),
      signal:  AbortSignal.timeout(8_000),
    });

    if (!res.ok) return null;
    return (await res.json()) as MLAnalysisResult;
  } catch {
    // Service unreachable — silent fallback
    return null;
  }
}

async function _persistMLResult(userId: string, r: MLAnalysisResult): Promise<void> {
  const alertGenerated = r.threat_score >= ALERT_THRESHOLD;
  const severity = _toSeverity(r.threat_score);

  await prisma.$transaction([
    // Update user risk fields
    prisma.user.update({
      where: { id: userId },
      data: {
        riskScore:    r.threat_score,
        isFlagged:    r.is_anomaly,
        lastAnalyzed: new Date(),
      },
    }),

    // Write full multi-layer RiskSnapshot
    prisma.riskSnapshot.create({
      data: {
        userId,
        threatScore:          r.threat_score,
        zScore:               r.z_score   ?? null,
        ifScore:              r.if_score  ?? null,
        lstmScore:            r.lstm_score ?? null,
        anomalyFlags:         r.anomaly_flags         ?? {},
        contributingFeatures: r.contributing_features ?? [],
        modelVersion:         r.model_version ?? "2.0.0",
        alertGenerated,
        severity,
      },
    }),

    // Mirror into UserSnapshot for the existing trend chart
    prisma.userSnapshot.create({
      data: {
        userId,
        riskScore:  r.threat_score,
        baseline:   r.if_score ?? 0,
        vectorData: {
          mlModel:    "Ensemble-v2",
          zScore:     r.z_score?.toFixed(2) ?? "N/A",
          ifScore:    r.if_score?.toFixed(2) ?? "N/A",
          lstmScore:  r.lstm_score?.toFixed(2) ?? "N/A",
          threatScore: r.threat_score,
          isAnomaly:  r.is_anomaly,
          timestamp:  new Date().toISOString(),
        },
      },
    }),
  ]);

  // Generate Alert if threshold crossed
  if (alertGenerated) {
    await _upsertAlert(userId, r.threat_score, severity, r.contributing_features ?? []);
  }

  console.log(
    `[ML ENGINE] user=${userId} threat=${r.threat_score} ` +
    `IF=${r.if_score?.toFixed(1)} LSTM=${r.lstm_score?.toFixed(1) ?? "—"} ` +
    `Z=${r.z_score?.toFixed(2) ?? "—"} alert=${alertGenerated}`
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Z-Score computation (Layer 1 — passed to FastAPI; also used by fallback path)
// ─────────────────────────────────────────────────────────────────────────────

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
      where:  { userId, createdAt: { gte: cutoff } },
      select: { action: true },
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

// ─────────────────────────────────────────────────────────────────────────────
// Z-Score fallback (Layer 1 only — used when FastAPI is unreachable)
// ─────────────────────────────────────────────────────────────────────────────

async function _zScoreFallback(userId: string): Promise<void> {
  const cutoff = new Date(Date.now() - WINDOW_DAYS * 24 * 60 * 60 * 1000);
  const [history, logs] = await Promise.all([
    prisma.userSnapshot.findMany({
      where:   { userId },
      orderBy: { createdAt: "desc" },
      take:    WINDOW_DAYS,
    }),
    prisma.activityLog.findMany({
      where: { userId, createdAt: { gte: cutoff } },
    }),
  ]);

  if (logs.length === 0) return;

  // Weighted raw risk: every event = 1pt, every DELETE = 25pt bonus
  const currentRisk =
    logs.length * 1 +
    logs.filter(l => String(l.action).includes("DELETE")).length * 25;

  let finalZ   = 0;
  let isAnomaly = false;

  if (history.length >= 3) {
    const historicalScores = history.map(h => h.riskScore);
    const avg    = mean(historicalScores);
    const stdDev = standardDeviation(historicalScores);

    if (stdDev > 0) {
      finalZ    = zScore(currentRisk, avg, stdDev);
      isAnomaly = finalZ > Z_THRESHOLD;
    }
  }

  const severity      = _toSeverity(currentRisk);
  const alertGenerated = isAnomaly && currentRisk >= ALERT_THRESHOLD;

  await prisma.$transaction([
    prisma.user.update({
      where: { id: userId },
      data: {
        riskScore:    Math.round(currentRisk),
        isFlagged:    isAnomaly,
        lastAnalyzed: new Date(),
      },
    }),

    prisma.riskSnapshot.create({
      data: {
        userId,
        threatScore:          Math.round(currentRisk),
        zScore:               finalZ,
        ifScore:              null,
        lstmScore:            null,
        anomalyFlags:         { zScore: isAnomaly, isoForest: false, lstm: false },
        contributingFeatures: [],
        modelVersion:         "1.0.0-zscore-fallback",
        alertGenerated,
        severity,
      },
    }),

    prisma.userSnapshot.create({
      data: {
        userId,
        riskScore: Math.round(currentRisk),
        baseline:  logs.length,
        vectorData: {
          mlModel:   "Z-Score-Fallback",
          zScore:    finalZ.toFixed(2),
          isAnomaly,
          timestamp: new Date().toISOString(),
        },
      },
    }),
  ]);

  if (alertGenerated) {
    await _upsertAlert(userId, Math.round(currentRisk), severity, []);
  }

  console.log(
    `[Z-SCORE FALLBACK] user=${userId} risk=${Math.round(currentRisk)} ` +
    `Z=${finalZ.toFixed(2)} anomaly=${isAnomaly}`
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Alert generation
// ─────────────────────────────────────────────────────────────────────────────

async function _upsertAlert(
  userId: string,
  threatScore: number,
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
  explanation: unknown[],
): Promise<void> {
  // Only create a new OPEN alert if there is no existing unresolved one
  const existing = await prisma.alert.findFirst({
    where: { userId, status: { in: ["OPEN", "ASSIGNED", "ACKNOWLEDGED"] } },
  });
  if (existing) return;

  await prisma.alert.create({
    data: {
      userId,
      riskScore:   threatScore,
      severity,
      confidence:  0.80,
      explanation: explanation as object[],
      status:      "OPEN",
    },
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

function _toSeverity(score: number): "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" {
  if (score >= 90) return "CRITICAL";
  if (score >= 70) return "HIGH";
  if (score >= 40) return "MEDIUM";
  return "LOW";
}

// ─────────────────────────────────────────────────────────────────────────────
// Type definitions
// ─────────────────────────────────────────────────────────────────────────────

interface MLAnalysisResult {
  user_id:              string;
  threat_score:         number;
  severity:             string;
  confidence:           number;
  is_anomaly:           boolean;
  // Per-layer scores
  z_score?:             number;
  if_score?:            number;
  lstm_score?:          number;
  // Flags and explanations
  anomaly_flags?:       Record<string, boolean>;
  contributing_features?: ContributingFeature[];
  model_version?:       string;
  analyzed_at:          string;
}

interface ContributingFeature {
  name:      string;
  label:     string;
  value:     number;
  impact:    number;
  direction: "increases_risk" | "decreases_risk";
}
