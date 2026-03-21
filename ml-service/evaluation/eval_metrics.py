"""
Sprint 2 — Evaluation: Precision, Recall, F1, ROC-AUC
========================================================
Measures detection quality against CMU CERT ground-truth labels.

Two evaluation modes:
  MODE A  — offline, from Parquet + trained models (no DB required):
              python -m evaluation.eval_metrics
  MODE B  — from Postgres RiskSnapshot table (reflects live system):
              python -m evaluation.eval_metrics --from-db

Output:
  • Classification report (precision / recall / F1 per class)
  • Confusion matrix
  • ROC-AUC score
  • Precision-recall AUC
  • FPR / FNR at default threshold (70)
  • JSON report saved to models/weights/eval_report.json

Threat score thresholds tested: [50, 60, 70, 75, 80, 85, 90]
"""

import argparse
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)

WEIGHTS_DIR  = Path(__file__).parent.parent / "models" / "weights"
REPORT_PATH  = WEIGHTS_DIR / "eval_report.json"
DEFAULT_THRESHOLD = 70


# ─────────────────────────────────────────────────────────────────────────────
# Score collection
# ─────────────────────────────────────────────────────────────────────────────

def _scores_from_parquet() -> tuple[np.ndarray, np.ndarray, list[str]]:
    """
    Build (y_true, y_scores, user_ids) by running the trained ensemble
    over the feature matrix from Parquet files.
    """
    from pipeline.features import load_feature_matrix
    from pipeline.ingest import load_ground_truth
    from models.ensemble import EnsembleModel

    X, user_ids = load_feature_matrix()
    if len(X) == 0:
        raise RuntimeError("Feature matrix is empty. Run ingest + transform first.")

    gt_df = load_ground_truth()
    if gt_df.empty:
        raise RuntimeError("Ground truth not found. answers/insiders.csv required.")

    malicious = set(gt_df["user_id"].tolist())
    y_true = np.array([1 if uid in malicious else 0 for uid in user_ids])

    ensemble = EnsembleModel()
    ensemble.load()
    if not ensemble.if_model.trained:
        raise RuntimeError("Models not trained. Run models/trainer.py first.")

    y_scores = np.zeros(len(user_ids))
    for i, (uid, fv) in enumerate(zip(user_ids, X)):
        try:
            result = ensemble.analyze_user(uid, fv)
            y_scores[i] = result["threat_score"]
        except Exception as e:
            logger.warning("Skipping user %s: %s", uid, e)

    return y_true, y_scores, user_ids


def _scores_from_db(database_url: Optional[str] = None) -> tuple[np.ndarray, np.ndarray, list[str]]:
    """
    Fetch threat scores from Postgres RiskSnapshot table.
    Uses the most recent snapshot per user.
    """
    from pipeline.ingest import load_ground_truth
    from sqlalchemy import create_engine, text

    url = database_url or os.environ.get("DATABASE_URL", "")
    if not url:
        raise RuntimeError("DATABASE_URL not set.")
    if "sslmode" not in url:
        url += ("&" if "?" in url else "?") + "sslmode=require"

    engine = create_engine(url, pool_pre_ping=True)
    with engine.connect() as conn:
        rows = conn.execute(text("""
            SELECT DISTINCT ON ("userId")
                "userId", "threatScore"
            FROM "RiskSnapshot"
            ORDER BY "userId", "createdAt" DESC
        """)).fetchall()

    if not rows:
        raise RuntimeError("No RiskSnapshot rows found. Run /analyze/batch first.")

    user_ids = [r[0] for r in rows]
    y_scores = np.array([float(r[1]) for r in rows])

    gt_df    = load_ground_truth()
    malicious = set(gt_df["user_id"].tolist()) if not gt_df.empty else set()
    y_true    = np.array([1 if uid in malicious else 0 for uid in user_ids])

    return y_true, y_scores, user_ids


# ─────────────────────────────────────────────────────────────────────────────
# Metric computation
# ─────────────────────────────────────────────────────────────────────────────

def _compute_metrics(
    y_true: np.ndarray,
    y_scores: np.ndarray,
    threshold: float = DEFAULT_THRESHOLD,
) -> dict:
    from sklearn.metrics import (
        classification_report, confusion_matrix,
        roc_auc_score, average_precision_score,
        precision_recall_curve,
    )

    y_pred = (y_scores >= threshold).astype(int)

    # Guard: need both classes present for ROC-AUC
    roc_auc = pr_auc = None
    if len(np.unique(y_true)) == 2:
        roc_auc = float(roc_auc_score(y_true, y_scores))
        pr_auc  = float(average_precision_score(y_true, y_scores))

    report_str = classification_report(y_true, y_pred,
                                       target_names=["benign", "malicious"],
                                       zero_division=0)
    report_dict = classification_report(y_true, y_pred,
                                        target_names=["benign", "malicious"],
                                        output_dict=True, zero_division=0)

    cm = confusion_matrix(y_true, y_pred)
    tn, fp, fn, tp = cm.ravel() if cm.size == 4 else (0, 0, 0, 0)

    fpr = fp / max(fp + tn, 1)   # false positive rate
    fnr = fn / max(fn + tp, 1)   # false negative rate (miss rate)

    return {
        "threshold":        threshold,
        "roc_auc":          round(roc_auc, 4) if roc_auc else None,
        "pr_auc":           round(pr_auc, 4)  if pr_auc  else None,
        "precision_malicious": round(report_dict["malicious"]["precision"], 4),
        "recall_malicious":    round(report_dict["malicious"]["recall"],    4),
        "f1_malicious":        round(report_dict["malicious"]["f1-score"],  4),
        "fpr":              round(fpr, 4),
        "fnr":              round(fnr, 4),
        "tp": int(tp), "fp": int(fp), "fn": int(fn), "tn": int(tn),
        "support": {"benign": int((y_true == 0).sum()), "malicious": int((y_true == 1).sum())},
        "classification_report": report_str,
    }


def _threshold_sweep(
    y_true: np.ndarray,
    y_scores: np.ndarray,
    thresholds: list[float] | None = None,
) -> list[dict]:
    thresholds = thresholds or [50, 60, 70, 75, 80, 85, 90]
    return [
        {
            "threshold": t,
            **{k: v for k, v in _compute_metrics(y_true, y_scores, t).items()
               if k in ("precision_malicious", "recall_malicious", "f1_malicious", "fpr", "fnr",
                        "tp", "fp", "fn", "tn")}
        }
        for t in thresholds
    ]


# ─────────────────────────────────────────────────────────────────────────────
# Top-level runner
# ─────────────────────────────────────────────────────────────────────────────

def run_evaluation(
    from_db: bool = False,
    threshold: float = DEFAULT_THRESHOLD,
    database_url: Optional[str] = None,
) -> dict:
    """
    Run the full evaluation and return a report dict.
    Also saves the report to models/weights/eval_report.json.
    """
    logger.info("Loading scores (source: %s)…", "postgres" if from_db else "parquet")

    if from_db:
        y_true, y_scores, user_ids = _scores_from_db(database_url)
    else:
        y_true, y_scores, user_ids = _scores_from_parquet()

    logger.info("Evaluating %d users  (malicious=%d, benign=%d)",
                len(y_true), int(y_true.sum()), int((y_true == 0).sum()))

    primary   = _compute_metrics(y_true, y_scores, threshold)
    sweep     = _threshold_sweep(y_true, y_scores)

    # Find best F1 threshold
    best = max(sweep, key=lambda x: x["f1_malicious"])

    report = {
        "evaluated_at":    datetime.now(timezone.utc).isoformat(),
        "n_users":         len(y_true),
        "n_malicious":     int(y_true.sum()),
        "source":          "postgres" if from_db else "parquet",
        "default_threshold_metrics": primary,
        "best_f1_threshold":         best["threshold"],
        "best_f1":                   best["f1_malicious"],
        "threshold_sweep":           sweep,
    }

    WEIGHTS_DIR.mkdir(parents=True, exist_ok=True)
    with open(REPORT_PATH, "w") as f:
        json.dump(report, f, indent=2, default=str)

    logger.info("Eval report saved to %s", REPORT_PATH)
    return report


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )
    parser = argparse.ArgumentParser(description="Evaluate detection model precision/recall.")
    parser.add_argument("--from-db",  action="store_true",
                        help="Pull scores from Postgres RiskSnapshot instead of Parquet.")
    parser.add_argument("--threshold", type=float, default=DEFAULT_THRESHOLD,
                        help=f"Classification threshold (default: {DEFAULT_THRESHOLD}).")
    parser.add_argument("--database-url", type=str, default=None)
    args = parser.parse_args()

    report = run_evaluation(
        from_db=args.from_db,
        threshold=args.threshold,
        database_url=args.database_url,
    )

    print("\n" + "=" * 60)
    print("EVALUATION REPORT")
    print("=" * 60)
    m = report["default_threshold_metrics"]
    print(m.get("classification_report", ""))
    print(f"ROC-AUC  : {m['roc_auc']}")
    print(f"PR-AUC   : {m['pr_auc']}")
    print(f"FPR      : {m['fpr']:.4f}  |  FNR: {m['fnr']:.4f}")
    print(f"\nBest F1 threshold: {report['best_f1_threshold']} → F1={report['best_f1']:.4f}")
    print("\nThreshold sweep:")
    for row in report["threshold_sweep"]:
        print(f"  t={row['threshold']:3.0f}  P={row['precision_malicious']:.3f}  "
              f"R={row['recall_malicious']:.3f}  F1={row['f1_malicious']:.3f}  "
              f"FPR={row['fpr']:.3f}  FNR={row['fnr']:.3f}")
