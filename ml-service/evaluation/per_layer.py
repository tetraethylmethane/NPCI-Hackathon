"""
ml-service/evaluation/per_layer.py
=====================================
Sprint 6 — Per-Layer Detection Metrics

Evaluates each detection layer in isolation so the report can show
the additive value of each layer in the ensemble.

Layers evaluated:
  1. Statistical (Z-Score)  — feature-13 (total_risk_weight) Z-score vs population
  2. Isolation Forest alone — IF anomaly score, threshold 70
  3. Ensemble (all layers)  — full EnsembleModel.analyze_user(), threshold 70

For each layer the function returns:
  precision, recall, F1, FPR, FNR, ROC-AUC (where applicable), confusion matrix
"""

import logging
from typing import Optional

import numpy as np

logger = logging.getLogger(__name__)

# Feature index of total_risk_weight (used for simple Z-score layer proxy)
_RISK_WEIGHT_IDX = 13   # matches FEATURE_NAMES in features.py


# ---------------------------------------------------------------------------
# Helper: convert raw scores to binary predictions at a threshold
# ---------------------------------------------------------------------------

def _binarize(scores: np.ndarray, threshold: float) -> np.ndarray:
    return (scores >= threshold).astype(int)


def _layer_metrics(
    y_true: np.ndarray,
    y_scores: np.ndarray,
    threshold: float,
    layer_name: str,
) -> dict:
    from sklearn.metrics import (
        precision_score, recall_score, f1_score,
        confusion_matrix, roc_auc_score,
    )

    y_pred = _binarize(y_scores, threshold)
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel() if cm.size == 4 else (0, 0, 0, 0)

    roc_auc = None
    if len(np.unique(y_true)) == 2:
        try:
            roc_auc = float(roc_auc_score(y_true, y_scores))
        except Exception:
            pass

    return {
        "layer":     layer_name,
        "threshold": threshold,
        "precision": round(float(precision_score(y_true, y_pred, zero_division=0)), 4),
        "recall":    round(float(recall_score(y_true, y_pred, zero_division=0)), 4),
        "f1":        round(float(f1_score(y_true, y_pred, zero_division=0)), 4),
        "fpr":       round(fp / max(fp + tn, 1), 4),
        "fnr":       round(fn / max(fn + tp, 1), 4),
        "roc_auc":   round(roc_auc, 4) if roc_auc is not None else None,
        "tp": int(tp), "fp": int(fp), "fn": int(fn), "tn": int(tn),
    }


# ---------------------------------------------------------------------------
# Layer 1 — Statistical Z-Score
# ---------------------------------------------------------------------------

def zscore_scores(X: np.ndarray, feature_idx: int = _RISK_WEIGHT_IDX) -> np.ndarray:
    """
    Compute Z-scores for a single feature column across the population,
    then map to [0, 100] with the same normalisation as the ensemble:
      z_norm = clip(z / 5.0 * 100, 0, 100)
    """
    col = X[:, feature_idx].astype(float)
    mu = col.mean()
    sigma = col.std() + 1e-9
    z = (col - mu) / sigma
    return np.clip(z / 5.0 * 100, 0, 100)


def evaluate_zscore_layer(
    X: np.ndarray,
    y_true: np.ndarray,
    threshold: float = 50.0,    # z_norm >= 50 → anomaly (z ≈ 2.5)
) -> dict:
    scores = zscore_scores(X)
    return _layer_metrics(y_true, scores, threshold, "Z-Score (Statistical)")


# ---------------------------------------------------------------------------
# Layer 2 — Isolation Forest alone
# ---------------------------------------------------------------------------

def evaluate_if_layer(
    X: np.ndarray,
    y_true: np.ndarray,
    threshold: float = 70.0,
) -> dict:
    from models.isolation_forest import IsolationForestModel

    model = IsolationForestModel()
    if not model.load():
        raise RuntimeError(
            "IsolationForest weights not found. Train the model first (POST /train)."
        )
    scores = model.predict_batch(X)
    return _layer_metrics(y_true, scores, threshold, "Isolation Forest")


# ---------------------------------------------------------------------------
# Layer 3 — Full Ensemble
# ---------------------------------------------------------------------------

def evaluate_ensemble_layer(
    X: np.ndarray,
    y_true: np.ndarray,
    user_ids: list[str],
    threshold: float = 70.0,
) -> dict:
    from models.ensemble import EnsembleModel

    ensemble = EnsembleModel()
    ensemble.load()
    if not ensemble.if_model.trained:
        raise RuntimeError("Ensemble not trained.")

    scores = np.zeros(len(user_ids))
    for i, (uid, fv) in enumerate(zip(user_ids, X)):
        try:
            result = ensemble.analyze_user(uid, fv)
            scores[i] = result["threat_score"]
        except Exception as e:
            logger.warning("Ensemble score failed for %s: %s", uid, e)

    return _layer_metrics(y_true, scores, threshold, "Ensemble (3-Layer)")


# ---------------------------------------------------------------------------
# Combined per-layer report
# ---------------------------------------------------------------------------

def evaluate_all_layers(
    X: np.ndarray,
    y_true: np.ndarray,
    user_ids: list[str],
    if_threshold: float = 70.0,
    zscore_threshold: float = 50.0,
    ensemble_threshold: float = 70.0,
) -> list[dict]:
    """
    Evaluate all three layers and return a list of metric dicts, one per layer.
    Gracefully skips layers where model weights are unavailable.
    """
    results: list[dict] = []

    # Layer 1 — Z-Score
    try:
        results.append(evaluate_zscore_layer(X, y_true, zscore_threshold))
        logger.info("Z-Score layer evaluated.")
    except Exception as e:
        logger.warning("Z-Score layer skipped: %s", e)

    # Layer 2 — Isolation Forest
    try:
        results.append(evaluate_if_layer(X, y_true, if_threshold))
        logger.info("Isolation Forest layer evaluated.")
    except Exception as e:
        logger.warning("IF layer skipped: %s", e)

    # Layer 3 — Ensemble
    try:
        results.append(evaluate_ensemble_layer(X, y_true, user_ids, ensemble_threshold))
        logger.info("Ensemble layer evaluated.")
    except Exception as e:
        logger.warning("Ensemble layer skipped: %s", e)

    return results
