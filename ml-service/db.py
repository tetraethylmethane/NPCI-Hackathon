"""
Sprint 2 — Postgres Writer
===========================
Writes ML results (RiskSnapshot, User risk score updates) from the Python
ML service back into Neon Postgres.

Shared with the Next.js side via the same DATABASE_URL connection string.
The ML service writes results directly; Next.js reads them for the dashboard.
"""

import json
import logging
import os
import time
import random
import string
from typing import Any

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)

_engine: Engine | None = None


def _get_engine() -> Engine:
    global _engine
    if _engine is None:
        url = os.environ.get("DATABASE_URL", "")
        if not url:
            raise RuntimeError("DATABASE_URL environment variable not set.")
        if "sslmode" not in url:
            url += ("&" if "?" in url else "?") + "sslmode=require"
        _engine = create_engine(url, pool_pre_ping=True, pool_size=3, max_overflow=2)
    return _engine


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

_CUID_CHARS = string.ascii_lowercase + string.digits

def _cuid() -> str:
    ts   = format(int(time.time() * 1000), "x")
    rand = "".join(random.choices(_CUID_CHARS, k=16))
    return f"c{ts}{rand}"


def _severity(score: int) -> str:
    if score >= 90: return "CRITICAL"
    if score >= 70: return "HIGH"
    if score >= 40: return "MEDIUM"
    return "LOW"


# ─────────────────────────────────────────────────────────────────────────────
# Write operations
# ─────────────────────────────────────────────────────────────────────────────

def write_risk_snapshot(
    user_id: str,
    threat_score: int,
    z_score: float | None,
    if_score: float | None,
    lstm_score: float | None,
    anomaly_flags: dict,
    contributing_features: list,
    model_version: str = "2.0.0",
    alert_generated: bool = False,
    feature_vector: dict | None = None,
) -> str:
    """
    Insert one RiskSnapshot row.  Returns the new snapshot id.
    feature_vector: output of pipeline.features.build_feature_payload() — stored in
    the RiskSnapshot.featureVector column for full lineage back to raw events.
    """
    severity     = _severity(threat_score)
    snap_id      = _cuid()

    with _get_engine().begin() as conn:
        conn.execute(text("""
            INSERT INTO "RiskSnapshot"
              (id, "userId", "threatScore", "zScore", "ifScore", "lstmScore",
               "anomalyFlags", "contributingFeatures", "featureVector", "modelVersion",
               "alertGenerated", severity, "createdAt")
            VALUES
              (:id, :uid, :threat, :z, :if_, :lstm,
               CAST(:flags AS jsonb), CAST(:features AS jsonb), CAST(:fvec AS jsonb),
               :ver, :alert, :sev, now())
        """), {
            "id":       snap_id,
            "uid":      user_id,
            "threat":   threat_score,
            "z":        z_score,
            "if_":      if_score,
            "lstm":     lstm_score,
            "flags":    json.dumps(anomaly_flags),
            "features": json.dumps(contributing_features, default=str),
            "fvec":     json.dumps(feature_vector, default=str) if feature_vector is not None else None,
            "ver":      model_version,
            "alert":    alert_generated,
            "sev":      severity,
        })

    logger.debug("RiskSnapshot written: user=%s  threat=%d  alert=%s",
                 user_id, threat_score, alert_generated)
    return snap_id


def update_user_risk(user_id: str, threat_score: int, is_flagged: bool) -> None:
    """Update User.riskScore, isFlagged, and lastAnalyzed."""
    with _get_engine().begin() as conn:
        conn.execute(text("""
            UPDATE "User"
            SET "riskScore"    = :score,
                "isFlagged"    = :flagged,
                "lastAnalyzed" = now(),
                "updatedAt"    = now()
            WHERE id = :uid
        """), {"score": threat_score, "flagged": is_flagged, "uid": user_id})


def create_alert_if_needed(
    user_id: str,
    threat_score: int,
    confidence: float,
    explanation: list,
) -> bool:
    """
    Create an Alert row only if no unresolved alert already exists for the user.
    Returns True if a new alert was created.
    """
    severity = _severity(threat_score)

    with _get_engine().begin() as conn:
        existing = conn.execute(text("""
            SELECT id FROM "Alert"
            WHERE "userId" = :uid
              AND status IN ('OPEN', 'ASSIGNED', 'ACKNOWLEDGED')
            LIMIT 1
        """), {"uid": user_id}).fetchone()

        if existing:
            return False

        conn.execute(text("""
            INSERT INTO "Alert"
              (id, "userId", "riskScore", severity, confidence,
               explanation, status, "createdAt", "updatedAt")
            VALUES
              (:id, :uid, :score, :sev, :conf,
               CAST(:expl AS jsonb), 'OPEN', now(), now())
        """), {
            "id":   _cuid(),
            "uid":  user_id,
            "score": threat_score,
            "sev":   severity,
            "conf":  round(confidence, 4),
            "expl":  json.dumps(explanation, default=str),
        })

    logger.info("Alert created: user=%s  score=%d  severity=%s",
                user_id, threat_score, severity)
    return True


def write_user_snapshot(
    user_id: str,
    threat_score: int,
    if_score: float | None,
    vector_data: dict,
) -> None:
    """Write a UserSnapshot row (for the existing trend chart in the dashboard)."""
    with _get_engine().begin() as conn:
        conn.execute(text("""
            INSERT INTO "UserSnapshot"
              (id, "userId", "riskScore", baseline, "vectorData", "createdAt")
            VALUES
              (:id, :uid, :score, :base, CAST(:vd AS jsonb), now())
        """), {
            "id":    _cuid(),
            "uid":   user_id,
            "score": threat_score,
            "base":  if_score or 0.0,
            "vd":    json.dumps(vector_data, default=str),
        })
