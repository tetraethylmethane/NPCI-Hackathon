"""
Sprint 7 — Alert Consumer
===========================
Consumes xcelit.alerts, upserts RiskSnapshot to Postgres, then fires
pg_notify('new_alert', payload) so the Next.js SSE endpoint can push
the alert to the dashboard without any polling loop.
"""

import json
import logging
import os
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

import psycopg2
import psycopg2.extras
from confluent_kafka import Consumer, KafkaError, KafkaException
from pydantic import ValidationError

sys.path.insert(0, str(Path(__file__).parent.parent))
from schemas import AlertEvent

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s — %(message)s")
logger = logging.getLogger(__name__)

ALERT_TOPIC  = os.environ.get("KAFKA_ALERTS_TOPIC", "xcelit.alerts")
GROUP_ID     = os.environ.get("KAFKA_ALERT_GROUP_ID", "alert-consumer-group")
DATABASE_URL = os.environ["DATABASE_URL"]


def _kafka_config() -> dict:
    return {
        "bootstrap.servers": os.environ["KAFKA_BOOTSTRAP_SERVERS"],
        "security.protocol": "SASL_SSL",
        "sasl.mechanism": "PLAIN",
        "sasl.username": os.environ["KAFKA_API_KEY"],
        "sasl.password": os.environ["KAFKA_API_SECRET"],
        "group.id": GROUP_ID,
        "auto.offset.reset": "earliest",
        "enable.auto.commit": False,
    }


def _new_cuid() -> str:
    return "c" + uuid.uuid4().hex[:24]


def _get_db_conn():
    url = DATABASE_URL
    if "sslmode" not in url:
        sep = "&" if "?" in url else "?"
        url = f"{url}{sep}sslmode=require"
    return psycopg2.connect(url)


def _upsert_risk_snapshot(conn, alert: AlertEvent, user_pg_id: str):
    """Insert a RiskSnapshot row for the alert."""
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO "RiskSnapshot"
              (id, "userId", "riskScore", "isFlagged", "vectorData", "createdAt")
            VALUES (%s, %s, %s, %s, %s::jsonb, %s)
            """,
            (
                _new_cuid(),
                user_pg_id,
                int(alert.risk_score),
                alert.flagged,
                json.dumps({
                    "mlModel": "Ensemble",
                    "ifScore": alert.if_score,
                    "rfProba": alert.rf_proba,
                    "topFeatures": alert.top_features,
                    "explanation": alert.explanation,
                    "timestamp": alert.timestamp.isoformat(),
                }),
                alert.timestamp.isoformat(),
            ),
        )
        # Update User.riskScore + isFlagged
        cur.execute(
            """
            UPDATE "User"
               SET "riskScore" = %s,
                   "isFlagged" = %s,
                   "lastAnalyzed" = %s,
                   "updatedAt" = now()
             WHERE id = %s
            """,
            (int(alert.risk_score), alert.flagged, alert.timestamp.isoformat(), user_pg_id),
        )
    conn.commit()


def _create_alert_row(conn, alert: AlertEvent, user_pg_id: str) -> str:
    """Insert an Alert row. Returns the new alert id."""
    alert_id = _new_cuid()
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO "Alert"
              (id, "userId", severity, status, explanation, "createdAt", "updatedAt")
            VALUES (%s, %s, %s, 'OPEN', %s, %s, %s)
            """,
            (
                alert_id,
                user_pg_id,
                alert.severity,
                json.dumps(alert.top_features),
                alert.timestamp.isoformat(),
                alert.timestamp.isoformat(),
            ),
        )
    conn.commit()
    return alert_id


def _pg_notify(conn, alert: AlertEvent, alert_id: str, user_pg_id: str):
    """Fire pg_notify('new_alert', json_payload) for SSE consumers."""
    payload = json.dumps({
        "alertId": alert_id,
        "userId": user_pg_id,
        "severity": alert.severity,
        "riskScore": alert.risk_score,
        "explanation": alert.explanation,
        "timestamp": alert.timestamp.isoformat(),
    })
    with conn.cursor() as cur:
        cur.execute("SELECT pg_notify('new_alert', %s)", (payload,))
    conn.commit()
    logger.info("pg_notify fired for alert %s (user=%s severity=%s)", alert_id, user_pg_id, alert.severity)


def _get_user_pg_id(conn, cert_user_id: str) -> str | None:
    email = f"{cert_user_id}@cert.local"
    with conn.cursor() as cur:
        cur.execute('SELECT id FROM "User" WHERE email = %s OR id = %s LIMIT 1', (email, cert_user_id))
        row = cur.fetchone()
        return row[0] if row else None


def run():
    consumer = Consumer(_kafka_config())
    consumer.subscribe([ALERT_TOPIC])
    logger.info("Alert consumer started — consuming %s", ALERT_TOPIC)

    db_conn = _get_db_conn()

    try:
        while True:
            msg = consumer.poll(timeout=1.0)
            if msg is None:
                continue
            if msg.error():
                if msg.error().code() == KafkaError._PARTITION_EOF:
                    continue
                raise KafkaException(msg.error())

            raw = msg.value()
            try:
                alert = AlertEvent.model_validate_json(raw)
            except ValidationError as e:
                logger.warning("Invalid alert schema: %s", e)
                consumer.commit(message=msg)
                continue

            try:
                if db_conn.closed:
                    db_conn = _get_db_conn()

                user_pg_id = _get_user_pg_id(db_conn, alert.user_id)
                if not user_pg_id:
                    logger.warning("User not found for alert: %s", alert.user_id)
                    consumer.commit(message=msg)
                    continue

                _upsert_risk_snapshot(db_conn, alert, user_pg_id)
                alert_id = _create_alert_row(db_conn, alert, user_pg_id)
                _pg_notify(db_conn, alert, alert_id, user_pg_id)

            except Exception as e:
                logger.error("Alert processing failed: %s", e)

            consumer.commit(message=msg)

    except KeyboardInterrupt:
        logger.info("Shutting down alert consumer.")
    finally:
        consumer.close()
        db_conn.close()


if __name__ == "__main__":
    run()
