"""
Ensemble Model — Score Fusion
------------------------------
Combines Isolation Forest (unsupervised) and Random Forest (supervised) scores.

Fusion formula:
  if RF trained:  risk = 0.6 × iso_score + 0.4 × (rf_proba × 100)
  else:           risk = iso_score   (fallback to unsupervised only)

Severity tiers (mirrors Alert.severity enum in Prisma):
  CRITICAL : risk >= 90
  HIGH     : risk >= 70
  MEDIUM   : risk >= 40
  LOW      : risk <  40
"""

import numpy as np
from datetime import datetime
from pathlib import Path

from models.isolation_forest import IsolationForestModel
from models.random_forest import RandomForestModel
from pipeline.features import FEATURE_NAMES


WEIGHT_IF = 0.6
WEIGHT_RF = 0.4


def risk_to_severity(risk: float) -> str:
    if risk >= 90:
        return "CRITICAL"
    if risk >= 70:
        return "HIGH"
    if risk >= 40:
        return "MEDIUM"
    return "LOW"


class EnsembleModel:
    def __init__(self):
        self.if_model = IsolationForestModel()
        self.rf_model = RandomForestModel()
        self.version = "1.0.0"
        self.trained_at: datetime | None = None

    def load(self) -> None:
        """Load persisted weights for both sub-models (if available)."""
        if_loaded = self.if_model.load()
        rf_loaded = self.rf_model.load()
        if if_loaded or rf_loaded:
            self.trained_at = datetime.utcnow()
        if not if_loaded:
            print("⚠️  IsolationForest weights not found — train before analyzing.")

    def train(
        self,
        X: np.ndarray,
        y: np.ndarray | None = None,
        version: str | None = None,
    ) -> dict:
        """
        Train the ensemble.

        Args:
            X: Feature matrix (n_users, 20)
            y: Optional labels — enables RF training (1 = malicious, 0 = benign)
            version: Optional version string for the model registry
        """
        if_result = {"model": "IsolationForest"}
        self.if_model.train(X)
        if_result["status"] = "trained"

        rf_result = {"model": "RandomForest"}
        if y is not None and len(np.unique(y)) == 2:
            rf_result["metrics"] = self.rf_model.train(X, y)
            rf_result["status"] = "trained"
        else:
            rf_result["status"] = "skipped (no labels)"

        self.trained_at = datetime.utcnow()
        if version:
            self.version = version

        return {"isolation_forest": if_result, "random_forest": rf_result, "version": self.version}

    def analyze_user(self, user_id: str, feature_vector: np.ndarray) -> dict:
        """
        Run full ensemble analysis for a single user.

        Returns:
          {
            user_id, risk_score, severity, confidence,
            if_score, rf_proba, is_anomaly,
            feature_vector, analyzed_at
          }
        """
        if not self.if_model.trained:
            raise RuntimeError("IsolationForest not trained. Run /train or load weights first.")

        if_score = self.if_model.predict_score(feature_vector)
        rf_proba = self.rf_model.predict_proba(feature_vector) if self.rf_model.trained else None

        if rf_proba is not None:
            risk = WEIGHT_IF * if_score + WEIGHT_RF * (rf_proba * 100)
            confidence = 0.85  # supervised + unsupervised agreement
        else:
            risk = if_score
            confidence = 0.65  # unsupervised only

        risk = float(np.clip(risk, 0, 100))
        severity = risk_to_severity(risk)

        return {
            "user_id": user_id,
            "risk_score": round(risk),
            "severity": severity,
            "confidence": round(confidence, 2),
            "if_score": round(if_score, 2),
            "rf_proba": round(rf_proba, 4) if rf_proba is not None else None,
            "is_anomaly": risk >= 70,
            "feature_vector": feature_vector.tolist(),
            "feature_names": FEATURE_NAMES,
            "analyzed_at": datetime.utcnow().isoformat(),
        }

    def status(self) -> dict:
        return {
            "version": self.version,
            "trained_at": self.trained_at.isoformat() if self.trained_at else None,
            "isolation_forest_ready": self.if_model.trained,
            "random_forest_ready": self.rf_model.trained,
            "fusion_weights": {"isolation_forest": WEIGHT_IF, "random_forest": WEIGHT_RF},
        }
