"""
Sprint 1 — Neon Postgres Seeder
=================================
Reads the normalised Parquet files produced by ingest.py + transform.py
and writes records into the existing ActivityLog and UserSnapshot tables
in Neon Postgres.

Strategy:
  1. Upsert a single sentinel Project ("CERT Dataset Seed") — all activity
     logs are anchored to this project since CERT data has no real projects.
  2. Upsert one User row per unique CERT user_id (email = user_id@cert.local).
  3. Batch-insert normalised events into ActivityLog in chunks of BATCH_SIZE.
  4. Batch-insert daily aggregated rows into UserSnapshot.
  5. Update User.riskScore + User.avgActionsDay from the profile summary.

Idempotency:
  - Project upsert is by name.
  - User upsert is by email.
  - ActivityLog inserts use ON CONFLICT DO NOTHING on (event_id) — requires
    adding a unique index on ActivityLog.event_id (migration note below).
  - UserSnapshot inserts are append-only (no dedup needed).

Run:
  python -m pipeline.seed_postgres
  python -m pipeline.seed_postgres --limit 50000   # first N events only
  python -m pipeline.seed_postgres --dry-run       # validate without writing

Migration note:
  Before running for the first time, add a unique index on ActivityLog so
  that duplicate event_ids from re-runs are safely skipped:

    ALTER TABLE "ActivityLog" ADD COLUMN IF NOT EXISTS "certEventId" TEXT;
    CREATE UNIQUE INDEX IF NOT EXISTS idx_actlog_cert_event
      ON "ActivityLog"("certEventId") WHERE "certEventId" IS NOT NULL;
"""

import argparse
import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import pandas as pd
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)

BATCH_SIZE = 5_000
CERT_PROJECT_NAME = "CERT Dataset Seed"
CERT_PROJECT_GITHUB = "https://github.com/cert/insider-threat-dataset"

# Map from our normalised action_type to Prisma ActivityType enum values
ACTION_TYPE_MAP: dict[str, str] = {
    "LOGON_SUCCESS":         "LOGON_SUCCESS",
    "LOGON_FAILURE":         "LOGON_FAILURE",
    "LOGOFF":                "LOGOFF",
    "USB_DEVICE_CONNECTED":  "USB_DEVICE_CONNECTED",
    "USB_DEVICE_DISCONNECT": "USB_DEVICE_CONNECTED",   # no DISCONNECT enum value
    "USB_FILE_COPY":         "USB_FILE_COPY",
    "FILE_ACCESS":           "FILE_UPLOADED",
    "FILE_COPY":             "USB_FILE_COPY",
    "FILE_DELETE":           "FILE_DELETED",
    "FILE_WRITE":            "FILE_UPLOADED",
    "EMAIL_SENT":            "EMAIL_SENT",
    "EMAIL_SENT_ATTACH":     "EMAIL_SENT",
    "EMAIL_RECEIVED":        "EMAIL_RECEIVED",
    "HTTP_VISIT":            "HTTP_VISIT",
    "HTTP_CLOUD":            "HTTP_VISIT",
    "HTTP_JOB_SITE":         "HTTP_VISIT",
}


# ---------------------------------------------------------------------------
# Connection
# ---------------------------------------------------------------------------

def get_engine(database_url: Optional[str] = None) -> Engine:
    url = database_url or os.environ.get("DATABASE_URL")
    if not url:
        raise RuntimeError(
            "DATABASE_URL not set. Export it or add it to .env in the repo root."
        )
    # Neon Postgres uses sslmode=require — ensure it's in the URL
    if "sslmode" not in url:
        connector = "&" if "?" in url else "?"
        url = f"{url}{connector}sslmode=require"
    return create_engine(url, pool_pre_ping=True, echo=False)


# ---------------------------------------------------------------------------
# Upsert helpers
# ---------------------------------------------------------------------------

def _upsert_project(conn, project_id_holder: list, owner_id: str = "") -> str:
    """Upsert the CERT sentinel project. Returns its id."""
    row = conn.execute(
        text('SELECT id FROM "Project" WHERE name = :name LIMIT 1'),
        {"name": CERT_PROJECT_NAME},
    ).fetchone()

    if row:
        pid = row[0]
        logger.info("CERT project already exists: %s", pid)
        project_id_holder.append(pid)
        return pid

    pid = _new_cuid()
    conn.execute(
        text("""
            INSERT INTO "Project" (id, name, "githubUrl", "userId", "createdAt", "updatedAt")
            VALUES (:id, :name, :github, :uid, now(), now())
            ON CONFLICT DO NOTHING
        """),
        {"id": pid, "name": CERT_PROJECT_NAME,
         "github": CERT_PROJECT_GITHUB, "uid": owner_id},
    )
    project_id_holder.append(pid)
    logger.info("Created CERT project: %s", pid)
    return pid


def _upsert_users(conn, user_ids: list[str]) -> dict[str, str]:
    """
    Upsert one User row per CERT user_id.
    Returns mapping: cert_user_id → postgres user id (same value for simplicity).
    """
    mapping = {}
    for cert_id in user_ids:
        email = f"{cert_id}@cert.local"
        row = conn.execute(
            text('SELECT id FROM "User" WHERE email = :email LIMIT 1'),
            {"email": email},
        ).fetchone()
        if row:
            mapping[cert_id] = row[0]
        else:
            uid = cert_id  # use CERT id as postgres id for traceability
            conn.execute(
                text("""
                    INSERT INTO "User"
                      (id, name, email, "createdAt", "updatedAt", role,
                       "onboardingCompleted", "riskScore", "avgActionsDay",
                       "isFlagged", status, "isMfaEnabled")
                    VALUES
                      (:id, :name, :email, now(), now(), 'USER',
                       false, 0, 0.0, false, 'ACTIVE', false)
                    ON CONFLICT (email) DO NOTHING
                """),
                {"id": uid, "name": f"CERT User {cert_id}", "email": email},
            )
            mapping[cert_id] = uid
    logger.info("Upserted %d users.", len(mapping))
    return mapping


# ---------------------------------------------------------------------------
# ActivityLog insert
# ---------------------------------------------------------------------------

def _insert_activity_logs(
    conn,
    normalized_df: pd.DataFrame,
    user_map: dict[str, str],
    project_id: str,
    dry_run: bool = False,
) -> int:
    """
    Batch-insert normalised events into ActivityLog.
    Skips rows whose CERT user_id isn't in user_map.
    Uses certEventId column for idempotency (ON CONFLICT DO NOTHING).
    """
    df = normalized_df.copy()
    df = df[df["user_id"].isin(user_map)]

    # Map cert user_id → postgres user id
    df["pg_user_id"] = df["user_id"].map(user_map)
    # Map action_type to Prisma enum
    df["pg_action"] = df["action_type"].map(ACTION_TYPE_MAP).fillna("HTTP_VISIT")

    rows_written = 0
    for i in range(0, len(df), BATCH_SIZE):
        batch = df.iloc[i : i + BATCH_SIZE]
        if dry_run:
            rows_written += len(batch)
            continue

        values = [
            {
                "id": _new_cuid(),
                "action": row["pg_action"],
                "description": _build_description(row),
                "metadata": row["metadata"],
                "user_id": row["pg_user_id"],
                "project_id": project_id,
                "created_at": row["timestamp"].isoformat(),
                "cert_event_id": row["event_id"],
            }
            for _, row in batch.iterrows()
        ]
        conn.execute(
            text("""
                INSERT INTO "ActivityLog"
                  (id, action, description, metadata, "userId", "projectId",
                   "createdAt", "certEventId")
                VALUES
                  (:id, :action, :description, CAST(:metadata AS jsonb),
                   :user_id, :project_id, :created_at, :cert_event_id)
                ON CONFLICT ("certEventId") DO NOTHING
            """),
            values,
        )
        rows_written += len(batch)
        logger.info("  ActivityLog batch %d/%d — %d rows",
                    i // BATCH_SIZE + 1, (len(df) // BATCH_SIZE) + 1, len(batch))

    return rows_written


def _build_description(row: pd.Series) -> str:
    meta = {}
    try:
        meta = json.loads(row.get("metadata", "{}") or "{}")
    except (json.JSONDecodeError, TypeError):
        pass
    src = row.get("source", "unknown")
    action = row.get("action_type", "")
    if src == "file":
        fn = meta.get("filename", "unknown file")
        return f"[CERT] File {action.lower().replace('_', ' ')}: {fn}"
    if src == "email":
        return f"[CERT] Email {action.lower().replace('_', ' ')} from {meta.get('from_addr', 'unknown')}"
    if src == "http":
        return f"[CERT] HTTP visit: {meta.get('url', 'unknown URL')[:120]}"
    if src == "device":
        return f"[CERT] Device {action.lower().replace('_', ' ')} on {row.get('pc', 'unknown PC')}"
    return f"[CERT] {src.capitalize()} {action.lower().replace('_', ' ')}"


# ---------------------------------------------------------------------------
# UserSnapshot insert
# ---------------------------------------------------------------------------

def _insert_user_snapshots(
    conn,
    daily_df: pd.DataFrame,
    user_map: dict[str, str],
    dry_run: bool = False,
) -> int:
    """Insert one UserSnapshot row per (user_id, date) from daily_snapshots."""
    df = daily_df.copy()
    df = df[df["user_id"].isin(user_map)]
    df["pg_user_id"] = df["user_id"].map(user_map)

    rows_written = 0
    for i in range(0, len(df), BATCH_SIZE):
        batch = df.iloc[i : i + BATCH_SIZE]
        if dry_run:
            rows_written += len(batch)
            continue

        values = [
            {
                "id": _new_cuid(),
                "user_id": row["pg_user_id"],
                "risk_score": int(row["total_risk_score"]),
                "baseline": float(row["total_events"]),
                "vector_data": json.dumps({
                    "mlModel": "ETL-DailyAggregate",
                    "source": "CERT",
                    "date": str(row["date"]),
                    "logon_risk": int(row.get("logon_risk", 0)),
                    "file_risk": int(row.get("file_risk", 0)),
                    "email_risk": int(row.get("email_risk", 0)),
                    "device_risk": int(row.get("device_risk", 0)),
                    "http_risk": int(row.get("http_risk", 0)),
                    "after_hours_events": int(row.get("after_hours_events", 0)),
                    "total_events": int(row["total_events"]),
                }),
                "created_at": pd.Timestamp(row["date"]).isoformat(),
            }
            for _, row in batch.iterrows()
        ]
        conn.execute(
            text("""
                INSERT INTO "UserSnapshot"
                  (id, "userId", "riskScore", baseline, "vectorData", "createdAt")
                VALUES
                  (:id, :user_id, :risk_score, :baseline,
                   CAST(:vector_data AS jsonb), :created_at)
            """),
            values,
        )
        rows_written += len(batch)

    logger.info("UserSnapshot: inserted %d daily rows.", rows_written)
    return rows_written


# ---------------------------------------------------------------------------
# User risk score update
# ---------------------------------------------------------------------------

def _update_user_risk_scores(
    conn,
    profiles_df: pd.DataFrame,
    user_map: dict[str, str],
    dry_run: bool = False,
) -> None:
    """Update User.riskScore and User.avgActionsDay from profile summaries."""
    for _, row in profiles_df.iterrows():
        uid = user_map.get(row["user_id"])
        if uid is None:
            continue
        if dry_run:
            continue
        conn.execute(
            text("""
                UPDATE "User"
                SET "riskScore" = :risk, "avgActionsDay" = :avg,
                    "lastAnalyzed" = now(), "updatedAt" = now()
                WHERE id = :uid
            """),
            {
                "risk": min(int(row["max_daily_risk"]), 100),
                "avg": float(row["avg_daily_risk"]),
                "uid": uid,
            },
        )


# ---------------------------------------------------------------------------
# Main seeder
# ---------------------------------------------------------------------------

def seed(
    limit: Optional[int] = None,
    dry_run: bool = False,
    database_url: Optional[str] = None,
    normalized_dir: Optional[Path] = None,
    aggregated_dir: Optional[Path] = None,
) -> dict:
    """
    Full seed run. Returns stats dict.

    Args:
        limit:     Cap on total ActivityLog rows to insert (for testing).
        dry_run:   Validate rows without writing to the database.
        database_url: Override DATABASE_URL env var.
        normalized_dir: Path to normalized Parquet files.
        aggregated_dir: Path to aggregated Parquet files.
    """
    from pipeline.ingest import load_all_normalized
    from pipeline.transform import load_daily_snapshots, load_user_profiles

    logger.info("=== CERT Postgres Seeder ===")
    logger.info("dry_run=%s  limit=%s", dry_run, limit)

    # Load Parquet inputs
    sources = load_all_normalized(normalized_dir)
    combined_frames = [df for df in sources.values() if not df.empty]
    if not combined_frames:
        raise RuntimeError("No normalized Parquet files found. Run ingest.run_pipeline() first.")

    combined = pd.concat(combined_frames, ignore_index=True)
    if limit:
        combined = combined.head(limit)
        logger.info("Limiting to first %d events.", limit)

    daily_df = load_daily_snapshots(aggregated_dir)
    profiles_df = load_user_profiles(aggregated_dir)

    unique_users = sorted(combined["user_id"].dropna().unique().tolist())
    logger.info("Unique CERT users to seed: %d", len(unique_users))

    engine = get_engine(database_url)
    stats = {}

    with engine.begin() as conn:
        # Users must exist before the sentinel project (FK constraint)
        user_map = _upsert_users(conn, unique_users)
        project_id_holder: list = []
        first_user_id = next(iter(user_map.values()))
        project_id = _upsert_project(conn, project_id_holder, owner_id=first_user_id)

        # Add certEventId column if missing (first run only)
        _ensure_cert_event_id_column(conn)

        al_rows = _insert_activity_logs(conn, combined, user_map, project_id, dry_run)
        snap_rows = _insert_user_snapshots(conn, daily_df, user_map, dry_run)
        _update_user_risk_scores(conn, profiles_df, user_map, dry_run)

    stats = {
        "dry_run": dry_run,
        "users_seeded": len(unique_users),
        "activity_log_rows": al_rows,
        "user_snapshot_rows": snap_rows,
        "project_id": project_id,
    }
    logger.info("Seed complete: %s", stats)
    return stats


def _ensure_cert_event_id_column(conn) -> None:
    """Add certEventId column + unique index on first run (idempotent DDL)."""
    conn.execute(text(
        'ALTER TABLE "ActivityLog" ADD COLUMN IF NOT EXISTS "certEventId" TEXT'
    ))
    conn.execute(text(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS idx_actlog_cert_event
          ON "ActivityLog"("certEventId")
         WHERE "certEventId" IS NOT NULL
        """
    ))


# ---------------------------------------------------------------------------
# CUID generator (lightweight, no external dependency)
# ---------------------------------------------------------------------------

import time
import random
import string

_CUID_CHARS = string.ascii_lowercase + string.digits


def _new_cuid() -> str:
    """Generate a cuid-compatible unique ID (simplified)."""
    ts = format(int(time.time() * 1000), "x")
    rand = "".join(random.choices(_CUID_CHARS, k=16))
    return f"c{ts}{rand}"


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )
    parser = argparse.ArgumentParser(description="Seed CERT data into Neon Postgres.")
    parser.add_argument("--limit", type=int, default=None,
                        help="Limit number of ActivityLog rows (useful for testing).")
    parser.add_argument("--dry-run", action="store_true",
                        help="Validate without writing to the database.")
    parser.add_argument("--database-url", type=str, default=None,
                        help="Override DATABASE_URL environment variable.")
    args = parser.parse_args()

    result = seed(
        limit=args.limit,
        dry_run=args.dry_run,
        database_url=args.database_url,
    )
    print(json.dumps(result, indent=2))
