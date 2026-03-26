"""
Shared Pydantic schemas for all Kafka messages.
Both the producer and consumers import from here.
"""

from datetime import datetime
from typing import Any, Literal, Optional
from pydantic import BaseModel


LogSource = Literal["logon", "file", "email", "http", "device"]


class RawLogEvent(BaseModel):
    """Message schema for the xcelit.raw-logs topic."""
    event_id: str
    user_id: str
    pc: str
    timestamp: datetime
    source: LogSource
    action_type: str
    metadata: dict[str, Any] = {}


class AlertEvent(BaseModel):
    """Message schema for the xcelit.alerts topic."""
    user_id: str
    risk_score: float
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    flagged: bool
    if_score: float
    rf_proba: float
    top_features: list[dict[str, Any]]
    explanation: str
    timestamp: datetime
    source_event_id: Optional[str] = None


class DeadLetterEvent(BaseModel):
    """Message schema for the xcelit.dead-letter topic."""
    original_topic: str
    original_payload: str
    failure_reason: str
    failed_at: datetime
