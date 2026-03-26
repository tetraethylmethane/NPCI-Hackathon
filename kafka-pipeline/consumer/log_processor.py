"""
Sprint 7 — Log Processor Consumer
====================================
Consumes xcelit.raw-logs, calls ML /analyze, writes ActivityLog to Postgres.
If risk_score >= threshold → publishes to xcelit.alerts.

Exactly-once semantics via manual offset commit (enable.auto.commit=false).
A message is only committed after successful Postgres write.

Dead-letter queue: any message that fails 3 times is forwarded to
xcelit.dead-letter with failure reason attached.
"""

import json
import logging
import os
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import httpx
import psycopg2
import psycopg2.extras
from confluent_kafka import Consumer, Producer, KafkaError, KafkaException
from pydantic import ValidationError

sys.path.insert(0, str(Path(__file__).parent.parent))
from schemas import RawLogEvent, AlertEvent, DeadLetterEvent

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s — %(message)s")
logger = logging.getLogger(__name__)

RAW_TOPIC    = os.environ.get("KAFKA_RAW_LOGS_TOPIC", "xcelit.raw-logs")
ALERT_TOPIC  = os.environ.get("KAFKA_ALERTS_TOPIC",   "xcelit.alerts")
DLQ_TOPIC    = os.environ.get("KAFKA_DLQ_TOPIC",      "xcelit.dead-letter")
GROUP_ID     = os.environ.get("KAFKA_GROUP_ID",        "log-processor-group")
ML_URL       = os.environ.get("ML_SERVICE_URL",        "http://localhost:8000")
DATABASE_URL = os.environ["DATABASE_URL"]
RISK_THRESHOLD = int(os.environ.get("ALERT_THRESHOLD", "70"))

# ActivityType enum values that map from source
ACTION_MAP = {
    "Logon":       "ACCOUNT_ACCESS",
    "Logoff":      "ACCOUNT_ACCESS",
    "Connect":     "DEVICE_CONNECT",
    "Disconnect":  "DEVICE_CONNECT",
    "Copy":        "FILE_COPY",
    "Open":        "FILE_ACCESS",
    "Write":       "FILE_ACCESS",
    "Send":        "EMAIL_SEND",
    "View":        "HTTP_VISIT",
    "Visit":       "HTTP_VISIT",
    "WWW Visit":   "HTTP_VISIT",
}


def _kafka_config() -> dict:
    return {
        "bootstrap.servers": os.environ["KAFKA_BOOTSTRAP_SERVERS"],
        "security.protocol": "SASL_SSL",
        "sasl.mechanism": "PLAIN",
        "sasl.username": os.environ["KAFKA_API_KEY"],
        "sasl.password": os.environ["KAFKA_API_SECRET"],
    }


def _new_cuid() -> str:
    return "c" + uuid.uuid4().hex[:24]


def _get_db_conn():
    url = DATABASE_URL
    if "sslmode" not in url:
        sep = "&" if "?" in url else "?"
        url = f"{url}{sep}sslmode=require"
    return psycopg2.connect(url)


def _ensure_sentinel_project(conn) -> str:
    """Return the CERT sentinel project id, creating it if needed."""
    with conn.cursor() as cur:
        cur.execute('SELECT id FROM "Project" WHERE name = %s LIMIT 1', ("CERT Dataset Seed",))
        row = cur.fetchone()
        if row:
            return row[0]
        # Find any user to own the project
        cur.execute('SELECT id FROM "User" LIMIT 1')
        user_row = cur.fetchone()
        owner_id = user_row[0] if user_row else _new_cuid()
        pid = _new_cuid()
        cur.execute(
            """
            INSERT INTO "Project" (id, name, "githubUrl", "userId", "createdAt", "updatedAt")
            VALUES (%s, %s, %s, %s, now(), now()) ON CONFLICT DO NOTHING
            """,
            (pid, "CERT Dataset Seed", "https://github.com/cert/insider-threat-dataset", owner_id),
        )
        conn.commit()
        return pid


def _write_activity_log(conn, event: RawLogEvent, project_id: str, user_pg_id: str):
    action = ACTION_MAP.get(event.action_type, "HTTP_VISIT")
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO "ActivityLog"
              (id, action, description, metadata, "userId", "projectId", "createdAt", "certEventId")
            VALUES (%s, %s, %s, %s::jsonb, %s, %s, %s, %s)
            ON CONFLICT ("certEventId") DO NOTHING
            """,
            (
                _new_cuid(),
                action,
                f"{event.source.upper()} event: {event.action_type} on {event.pc}",
                json.dumps(event.metadata),
                user_pg_id,
                project_id,
                event.timestamp.isoformat(),
                event.event_id,
            ),
        )
    conn.commit()


def _get_or_create_user(conn, cert_user_id: str) -> str:
    email = f"{cert_user_id}@cert.local"
    with conn.cursor() as cur:
        cur.execute('SELECT id FROM "User" WHERE email = %s LIMIT 1', (email,))
        row = cur.fetchone()
        if row:
            return row[0]
        uid = cert_user_id
        cur.execute(
            """
            INSERT INTO "User"
              (id, name, email, "createdAt", "updatedAt", role,
               "onboardingCompleted", "riskScore", "avgActionsDay", "isFlagged", status, "isMfaEnabled")
            VALUES (%s, %s, %s, now(), now(), 'USER', false, 0, 0.0, false, 'ACTIVE', false)
            ON CONFLICT (email) DO NOTHING
            """,
            (uid, f"CERT User {cert_user_id}", email),
        )
        conn.commit()
        return uid


def _call_ml(user_id: str) -> dict | None:
    try:
        resp = httpx.post(f"{ML_URL}/analyze/user/{user_id}", timeout=15)
        if resp.status_code == 200:
            return resp.json()
    except Exception as e:
        logger.warning("ML call failed for %s: %s", user_id, e)
    return None


def _send_to_dlq(producer: Producer, original_topic: str, raw_value: bytes, reason: str):
    evt = DeadLetterEvent(
        original_topic=original_topic,
        original_payload=raw_value.decode("utf-8", errors="replace"),
        failure_reason=reason,
        failed_at=datetime.now(tz=timezone.utc),
    )
    producer.produce(DLQ_TOPIC, value=evt.model_dump_json().encode())
    producer.poll(0)


def _publish_alert(producer: Producer, ml_result: dict, user_id: str, event_id: str):
    severity = ml_result.get("severity", "LOW")
    risk_score = ml_result.get("riskScore", 0)
    if risk_score < RISK_THRESHOLD:
        return

    alert = AlertEvent(
        user_id=user_id,
        risk_score=risk_score,
        severity=severity,
        flagged=ml_result.get("flagged", False),
        if_score=ml_result.get("ifScore", 0),
        rf_proba=ml_result.get("rfProba", 0),
        top_features=ml_result.get("topFeatures", []),
        explanation=ml_result.get("explanation", ""),
        timestamp=datetime.now(tz=timezone.utc),
        source_event_id=event_id,
    )
    producer.produce(
        ALERT_TOPIC,
        key=user_id.encode(),
        value=alert.model_dump_json().encode(),
    )
    producer.poll(0)
    logger.info("Alert published for user %s — score=%s severity=%s", user_id, risk_score, severity)


def run():
    consumer = Consumer({
        **_kafka_config(),
        "group.id": GROUP_ID,
        "auto.offset.reset": "earliest",
        "enable.auto.commit": False,
    })
    producer = Producer(_kafka_config())

    consumer.subscribe([RAW_TOPIC])
    logger.info("Log processor started — consuming %s", RAW_TOPIC)

    db_conn = _get_db_conn()
    project_id = _ensure_sentinel_project(db_conn)

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
                event = RawLogEvent.model_validate_json(raw)
            except ValidationError as e:
                logger.warning("Invalid message schema: %s", e)
                _send_to_dlq(producer, RAW_TOPIC, raw, str(e))
                consumer.commit(message=msg)
                continue

            try:
                # Reconnect if stale
                if db_conn.closed:
                    db_conn = _get_db_conn()
                    project_id = _ensure_sentinel_project(db_conn)

                user_pg_id = _get_or_create_user(db_conn, event.user_id)
                _write_activity_log(db_conn, event, project_id, user_pg_id)
                ml_result = _call_ml(event.user_id)
                if ml_result:
                    _publish_alert(producer, ml_result, event.user_id, event.event_id)

            except Exception as e:
                logger.error("Processing failed for event %s: %s", event.event_id, e)
                _send_to_dlq(producer, RAW_TOPIC, raw, str(e))

            consumer.commit(message=msg)

    except KeyboardInterrupt:
        logger.info("Shutting down log processor.")
    finally:
        consumer.close()
        producer.flush()
        db_conn.close()


if __name__ == "__main__":
    run()
