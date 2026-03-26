"""
Sprint 7 — Kafka Log Producer
==============================
Reads all five CMU CERT log CSV files and streams each row as a RawLogEvent
to the xcelit.raw-logs Kafka topic, partitioned by user_id.

Guarantees:
  - acks=all          → message written to all in-sync replicas
  - gzip compression  → reduced bandwidth to Confluent Cloud
  - Ordered per user  → same user_id always goes to the same partition

Usage:
    python -m producer.log_producer --dataset-dir ../dataset
    python -m producer.log_producer --dataset-dir ../dataset --limit 5000
"""

import argparse
import csv
import json
import logging
import os
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

from confluent_kafka import Producer, KafkaException
from pydantic import ValidationError

sys.path.insert(0, str(Path(__file__).parent.parent))
from schemas import RawLogEvent

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s — %(message)s")
logger = logging.getLogger(__name__)

TOPIC = os.environ.get("KAFKA_RAW_LOGS_TOPIC", "xcelit.raw-logs")

# Map CSV filenames → source label + action_type column
SOURCE_CONFIG: dict[str, dict] = {
    "logon.csv":  {"source": "logon",  "action_col": "activity",  "extra": []},
    "device.csv": {"source": "device", "action_col": "activity",  "extra": []},
    "file.csv":   {"source": "file",   "action_col": "activity",  "extra": ["filename"]},
    "email.csv":  {"source": "email",  "action_col": "activity",  "extra": ["to", "from", "size", "attachments"]},
    "http.csv":   {"source": "http",   "action_col": "activity",  "extra": ["url", "content"]},
}

TS_FORMATS = [
    "%m/%d/%Y %H:%M:%S",
    "%Y-%m-%d %H:%M:%S",
    "%m/%d/%Y %H:%M",
]


def _parse_ts(raw: str) -> datetime:
    for fmt in TS_FORMATS:
        try:
            return datetime.strptime(raw.strip(), fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return datetime.now(tz=timezone.utc)


def _delivery_report(err, msg):
    if err:
        logger.error("Delivery failed for %s: %s", msg.key(), err)


def _build_producer() -> Producer:
    bootstrap = os.environ["KAFKA_BOOTSTRAP_SERVERS"]
    api_key = os.environ["KAFKA_API_KEY"]
    api_secret = os.environ["KAFKA_API_SECRET"]

    return Producer({
        "bootstrap.servers": bootstrap,
        "security.protocol": "SASL_SSL",
        "sasl.mechanism": "PLAIN",
        "sasl.username": api_key,
        "sasl.password": api_secret,
        "compression.type": "gzip",
        "acks": "all",
        "retries": 5,
        "retry.backoff.ms": 500,
    })


def produce(dataset_dir: Path, limit: int | None = None) -> int:
    producer = _build_producer()
    total = 0

    for csv_name, cfg in SOURCE_CONFIG.items():
        path = dataset_dir / csv_name
        if not path.exists():
            logger.warning("Skipping %s — file not found", csv_name)
            continue

        source = cfg["source"]
        action_col = cfg["action_col"]
        extra_cols = cfg["extra"]
        count = 0

        logger.info("Streaming %s → %s", csv_name, TOPIC)

        with open(path, newline="", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            for row in reader:
                if limit and total >= limit:
                    break

                metadata: dict = {}
                for col in extra_cols:
                    if col in row:
                        metadata[col] = row[col]

                try:
                    event = RawLogEvent(
                        event_id=row.get("id") or str(uuid.uuid4()),
                        user_id=row.get("user", "unknown"),
                        pc=row.get("pc", ""),
                        timestamp=_parse_ts(row.get("date", "")),
                        source=source,
                        action_type=row.get(action_col, "UNKNOWN"),
                        metadata=metadata,
                    )
                except ValidationError as e:
                    logger.debug("Schema error on row %s: %s", row.get("id"), e)
                    continue

                payload = event.model_dump_json().encode("utf-8")
                producer.produce(
                    topic=TOPIC,
                    key=event.user_id.encode("utf-8"),   # partition by user
                    value=payload,
                    on_delivery=_delivery_report,
                )

                # Poll to trigger delivery callbacks
                producer.poll(0)
                count += 1
                total += 1

        logger.info("  %s: %d events queued", source, count)
        producer.flush()

    logger.info("Producer done — %d total events sent to %s", total, TOPIC)
    return total


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CERT log producer → Kafka")
    parser.add_argument("--dataset-dir", default="../dataset", help="Directory containing CMU CSV files")
    parser.add_argument("--limit", type=int, default=None, help="Max events to produce (all sources combined)")
    args = parser.parse_args()

    produced = produce(Path(args.dataset_dir), limit=args.limit)
    sys.exit(0 if produced > 0 else 1)
