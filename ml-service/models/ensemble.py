"""
Sprint 2 — Ensemble Model: 3-Layer Score Fusion
=================================================
Combines all three detection layers into a single composite threat_score.

Layer weights (configurable, must sum to 1.0):
  Layer 1 — Z-Score (statistical):          0.20
  Layer 2 — Isolation Forest (unsupervised): 0.40
  Layer 3 — LSTM Autoencoder (sequential):   0.40

Graceful degradation:
  If LSTM not trained:   IF weight = 0.70, Z-Score = 0.30
  If neither RF trained: IF uses raw anomaly score only
  Z-Score is always computed server-side in analysis.ts.
  The Python service receives it via the /analyze request body (optional).

Severity tiers match Prisma AlertSeverity enum:
  CRITICAL : threat_score >= 90
  HIGH     : threat_score >= 70   ← Alert generated above this line
  MEDIUM   : threat_score >= 40
  LOW      : threat_score <  40
"""

import logging
from datetime import datetime, timezone

import numpy as np

from models.isolation_forest import IsolationForestModel
from models.random_forest import RandomForestModel
from models.lstm_autoencoder import LSTMAutoencoderModel
from pipeline.features import FEATURE_NAMES

logger = logging.getLogger(__name__)

# ── Layer weights ─────────────────────────────────────────────────────────────
W_ZSCORE_3LAYER = 0.20
W_IF_3LAYER     = 0.40
W_LSTM_3LAYER   = 0.40

W_ZSCORE_2LAYER = 0.30    # fallback when LSTM unavailable
W_IF_2LAYER     = 0.70

ALERT_THRESHOLD = 70      # threat_score >= this → alertGenerated = True
MODEL_VERSION   = "2.0.0"


def risk_to_severity(score: float) -> str:
    if score >= 90: return "CRITICAL"
    if score >= 70: return "HIGH"
    if score >= 40: return "MEDIUM"
    return "LOW"


def _normalize_zscore(z: float | None) -> float:
    """Map raw Z-Score to [0, 100]. Z=2.5 → 50, Z=5.0 → 100, negative → 0."""
    if z is None:
        return 0.0
    return float(np.clip(z / 5.0 * 100, 0, 100))


# ─────────────────────────────────────────────────────────────────────────────

class EnsembleModel:
    def __init__(self):
        self.if_model   = IsolationForestModel()
        self.rf_model   = RandomForestModel()
        self.lstm_model = LSTMAutoencoderModel()
        self.version    = MODEL_VERSION
        self.trained_at: datetime | None = None

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def load(self) -> None:
        """Load persisted weights for all sub-models."""
        if_ok   = self.if_model.load()
        _       = self.rf_model.load()       # optional
        lstm_ok = self.lstm_model.load()     # optional

        if if_ok:
            self.trained_at = datetime.now(timezone.utc)
            logger.info("Ensemble loaded. IF=✓  RF=%s  LSTM=%s",
                        "✓" if self.rf_model.trained else "—",
                        "✓" if lstm_ok else "—")
        else:
            logger.warning("IsolationForest weights not found — run POST /train first.")

    def train(
        self,
        X: np.ndarray,
        sequences: np.ndarray | None = None,
        y: np.ndarray | None = None,
        version: str | None = None,
    ) -> dict:
        """
        Train the full ensemble.

        Args:
            X:          Feature matrix (n_users, 20) for IF and RF.
            sequences:  Sequence array (n_users, 30, 8) for LSTM. Optional.
            y:          Binary ground-truth labels (1=malicious). Optional.
            version:    Version tag for model registry.
        """
        results = {}

        # Layer 2 — Isolation Forest (always trained — no labels needed)
        logger.info("Training Isolation Forest…")
        self.if_model.train(X)
        results["isolation_forest"] = {"status": "trained", "users": len(X)}

        # Layer 2b — Random Forest (supervised, only when labels available)
        if y is not None and len(np.unique(y)) == 2:
            logger.info("Training Random Forest (supervised)…")
            rf_metrics = self.rf_model.train(X, y)
            results["random_forest"] = {"status": "trained", "metrics": rf_metrics}
        else:
            results["random_forest"] = {"status": "skipped", "reason": "no ground-truth labels"}

        # Layer 3 — LSTM Autoencoder (optional)
        if sequences is not None and len(sequences) > 0:
            logger.info("Training LSTM Autoencoder…")
            lstm_result = self.lstm_model.train(sequences, y)
            results["lstm_autoencoder"] = lstm_result
        else:
            results["lstm_autoencoder"] = {"status": "skipped", "reason": "no sequences provided"}

        self.trained_at = datetime.now(timezone.utc)
        if version:
            self.version = version

        results["version"]    = self.version
        results["trained_at"] = self.trained_at.isoformat()
        return results

    # ── Inference ─────────────────────────────────────────────────────────────

    def analyze_user(
        self,
        user_id: str,
        feature_vector: np.ndarray,
        sequence: np.ndarray | None = None,
        z_score_external: float | None = None,
    ) -> dict:
        """
        Run all available detection layers and return composite threat_score.

        Args:
            user_id:          CERT or Postgres user identifier.
            feature_vector:   20-dim feature vector (output of features.extract_features).
            sequence:         (30, 8) daily sequence array for LSTM layer. Optional.
            z_score_external: Pre-computed Z-Score from Next.js layer 1. Optional.

        Returns:
            Full analysis result dict — matches MLAnalysisResult interface in analysis.ts.
        """
        if not self.if_model.trained:
            raise RuntimeError(
                "IsolationForest is not trained. "
                "POST /train or run ml-service/models/trainer.py first."
            )

        # ── Layer 2: Isolation Forest ──────────────────────────────────────────
        if_score  = self.if_model.predict_score(feature_vector)
        rf_proba  = self.rf_model.predict_proba(feature_vector) if self.rf_model.trained else None

        # Blend IF + RF for a refined Layer-2 score when RF is available
        if rf_proba is not None:
            layer2_score = 0.55 * if_score + 0.45 * (rf_proba * 100)
        else:
            layer2_score = if_score

        # ── Layer 3: LSTM Autoencoder ──────────────────────────────────────────
        lstm_score: float | None = None
        if self.lstm_model.trained and sequence is not None:
            lstm_score = self.lstm_model.anomaly_score(sequence)
        elif self.lstm_model.trained:
            logger.debug("LSTM trained but no sequence provided for user %s", user_id)

        # ── Layer 1: Z-Score (normalised) ──────────────────────────────────────
        z_norm = _normalize_zscore(z_score_external)

        # ── Score fusion ───────────────────────────────────────────────────────
        if lstm_score is not None:
            # All 3 layers active
            threat_score = (
                W_ZSCORE_3LAYER * z_norm +
                W_IF_3LAYER     * layer2_score +
                W_LSTM_3LAYER   * lstm_score
            )
            confidence = 0.88
            layers_active = ["zscore", "isolation_forest", "lstm"]
        else:
            # 2-layer mode (no LSTM)
            threat_score = (
                W_ZSCORE_2LAYER * z_norm +
                W_IF_2LAYER     * layer2_score
            )
            confidence = 0.72
            layers_active = ["zscore", "isolation_forest"]

        threat_score = float(np.clip(threat_score, 0, 100))
        severity     = risk_to_severity(threat_score)
        is_anomaly   = threat_score >= ALERT_THRESHOLD

        anomaly_flags = {
            "zScore":       bool(z_score_external is not None and z_score_external > 2.5),
            "isoForest":    bool(if_score >= 70),
            "lstm":         bool(lstm_score is not None and lstm_score >= 70),
        }

        return {
            "user_id":              user_id,
            "threat_score":         round(threat_score),
            # Keep risk_score alias for backwards compat with existing dashboard code
            "risk_score":           round(threat_score),
            "severity":             severity,
            "confidence":           round(confidence, 2),
            "is_anomaly":           is_anomaly,
            # Per-layer scores
            "z_score":              round(z_score_external, 4) if z_score_external is not None else None,
            "if_score":             round(layer2_score, 2),
            "lstm_score":           round(lstm_score, 2) if lstm_score is not None else None,
            # Breakdown
            "anomaly_flags":        anomaly_flags,
            "layers_active":        layers_active,
            "contributing_features": [],   # filled by SHAPExplainer in routes.py
            "feature_vector":       feature_vector.tolist(),
            "feature_names":        FEATURE_NAMES,
            "model_version":        self.version,
            "analyzed_at":          datetime.now(timezone.utc).isoformat(),
        }

    # ── Status ────────────────────────────────────────────────────────────────

    def status(self) -> dict:
        return {
            "version":               self.version,
            "trained_at":            self.trained_at.isoformat() if self.trained_at else None,
            "isolation_forest_ready": self.if_model.trained,
            "random_forest_ready":    self.rf_model.trained,
            "lstm_ready":             self.lstm_model.trained,
            "fusion_weights": {
                "z_score":          W_ZSCORE_3LAYER if self.lstm_model.trained else W_ZSCORE_2LAYER,
                "isolation_forest": W_IF_3LAYER     if self.lstm_model.trained else W_IF_2LAYER,
                "lstm":             W_LSTM_3LAYER   if self.lstm_model.trained else 0.0,
            },
            "alert_threshold": ALERT_THRESHOLD,
        }
