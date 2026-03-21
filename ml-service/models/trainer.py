"""
Sprint 2 — Offline Training Orchestrator
==========================================
Trains all three detection layers on CERT data and serialises the weights
to ml-service/models/weights/.

Run AFTER Sprint 1 ETL pipeline has produced Parquet files:
  python -m models.trainer              # trains all layers
  python -m models.trainer --no-lstm    # skip LSTM (if torch not installed)
  python -m models.trainer --eval       # run evaluation after training

Prerequisites:
  dataset/processed/normalized/*.parquet   (from ingest.run_pipeline)
  dataset/processed/aggregated/*.parquet   (from transform.build_aggregates)

Output:
  models/weights/isolation_forest.joblib
  models/weights/scaler_if.joblib
  models/weights/random_forest.joblib     (only if ground truth available)
  models/weights/scaler_rf.joblib
  models/weights/lstm_autoencoder.pt      (only if torch installed)
  models/weights/lstm_threshold.npy
  models/weights/training_report.json
"""

import argparse
import json
import logging
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

logger = logging.getLogger(__name__)

WEIGHTS_DIR = Path(__file__).parent / "weights"
WEIGHTS_DIR.mkdir(exist_ok=True)


def run_training(skip_lstm: bool = False, run_eval: bool = False) -> dict:
    from pipeline.features import load_feature_matrix
    from pipeline.ingest import load_ground_truth
    from pipeline.transform import load_daily_snapshots
    from models.isolation_forest import IsolationForestModel
    from models.random_forest import RandomForestModel
    from models.lstm_autoencoder import LSTMAutoencoderModel, build_sequences_from_daily

    report: dict = {
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "layers": {},
    }

    # ── Load data ──────────────────────────────────────────────────────────────
    logger.info("Loading feature matrix from Parquet…")
    t0 = time.perf_counter()
    X, user_ids = load_feature_matrix()
    logger.info("Feature matrix: %s  (%.1fs)", X.shape, time.perf_counter() - t0)

    # Ground truth labels
    gt_df = load_ground_truth()
    y: np.ndarray | None = None
    if not gt_df.empty:
        malicious = set(gt_df["user_id"].tolist())
        y = np.array([1 if uid in malicious else 0 for uid in user_ids])
        logger.info("Ground truth: %d malicious / %d benign users",
                    int(y.sum()), int((y == 0).sum()))
    else:
        logger.warning("No ground truth found — RF training skipped, LSTM trains on all users.")

    # ── Layer 2: Isolation Forest ──────────────────────────────────────────────
    logger.info("━━━ Training Isolation Forest ━━━")
    t0 = time.perf_counter()
    if_model = IsolationForestModel(contamination=0.05)
    if_model.train(X)
    report["layers"]["isolation_forest"] = {
        "status": "trained",
        "n_users": len(X),
        "elapsed_s": round(time.perf_counter() - t0, 1),
    }
    logger.info("IF trained in %.1fs", time.perf_counter() - t0)

    # ── Layer 2b: Random Forest ────────────────────────────────────────────────
    if y is not None and len(np.unique(y)) == 2:
        logger.info("━━━ Training Random Forest ━━━")
        t0 = time.perf_counter()
        rf_model = RandomForestModel()
        rf_metrics = rf_model.train(X, y)
        report["layers"]["random_forest"] = {
            "status": "trained",
            "elapsed_s": round(time.perf_counter() - t0, 1),
            **rf_metrics,
        }
        logger.info("RF ROC-AUC: %.3f ± %.3f",
                    rf_metrics["roc_auc_mean"], rf_metrics["roc_auc_std"])
    else:
        report["layers"]["random_forest"] = {"status": "skipped", "reason": "no labels"}

    # ── Layer 3: LSTM Autoencoder ──────────────────────────────────────────────
    if not skip_lstm:
        logger.info("━━━ Training LSTM Autoencoder ━━━")
        try:
            daily_df = load_daily_snapshots()
        except FileNotFoundError:
            logger.warning("daily_snapshots.parquet not found — LSTM skipped.")
            report["layers"]["lstm"] = {"status": "skipped", "reason": "no daily snapshots"}
            daily_df = None

        if daily_df is not None:
            t0 = time.perf_counter()
            sequences, seq_user_ids = build_sequences_from_daily(daily_df)
            logger.info("Sequences built: %s", sequences.shape)

            # Align labels to sequence order
            seq_y: np.ndarray | None = None
            if y is not None and gt_df is not None:
                mal_set = set(gt_df["user_id"].tolist())
                seq_y = np.array([1 if uid in mal_set else 0 for uid in seq_user_ids])

            lstm_model = LSTMAutoencoderModel(epochs=50, patience=7)
            lstm_result = lstm_model.train(sequences, seq_y)
            lstm_result["elapsed_s"] = round(time.perf_counter() - t0, 1)
            report["layers"]["lstm"] = lstm_result
    else:
        report["layers"]["lstm"] = {"status": "skipped", "reason": "--no-lstm flag set"}

    # ── Evaluation ────────────────────────────────────────────────────────────
    if run_eval:
        logger.info("━━━ Running Evaluation ━━━")
        try:
            from evaluation.eval_metrics import run_evaluation
            eval_report = run_evaluation()
            report["evaluation"] = eval_report
        except Exception as e:
            logger.warning("Evaluation failed: %s", e)
            report["evaluation"] = {"error": str(e)}

    # ── Save training report ───────────────────────────────────────────────────
    report_path = WEIGHTS_DIR / "training_report.json"
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)
    logger.info("Training report saved to %s", report_path)

    return report


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )

    parser = argparse.ArgumentParser(description="Train NPCI PS3 detection models.")
    parser.add_argument("--no-lstm", action="store_true",
                        help="Skip LSTM training (use if PyTorch not installed).")
    parser.add_argument("--eval", action="store_true",
                        help="Run precision/recall evaluation after training.")
    args = parser.parse_args()

    result = run_training(skip_lstm=args.no_lstm, run_eval=args.eval)
    print("\n" + "=" * 60)
    print("TRAINING COMPLETE")
    print("=" * 60)
    print(json.dumps(result, indent=2, default=str))
