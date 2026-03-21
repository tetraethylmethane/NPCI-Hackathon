"""
Sprint 2 — FastAPI Routes
==========================
Primary endpoint: POST /analyze/user/{user_id}
  Runs all 3 detection layers, writes RiskSnapshot + Alert to Postgres,
  returns full threat assessment dict matching the MLAnalysisResult
  TypeScript interface in lib/analysis.ts.

All endpoints are documented at http://localhost:8000/docs
"""

import json
import logging
from pathlib import Path

import numpy as np
from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel

from db import write_risk_snapshot, update_user_risk, create_alert_if_needed, write_user_snapshot
from evaluation.eval_metrics import run_evaluation
from models.trainer import run_training
from models.lstm_autoencoder import build_sequences_from_daily
from pipeline.features import get_user_vector, load_feature_matrix, build_feature_payload
from pipeline.ingest import run_pipeline
from pipeline.transform import load_daily_snapshots

logger = logging.getLogger(__name__)
router = APIRouter()

# ── Module-level singletons (injected by main.py at startup) ─────────────────
_ensemble = None
_explainer = None


def set_models(ensemble, explainer) -> None:
    global _ensemble, _explainer
    _ensemble = ensemble
    _explainer = explainer


# ─────────────────────────────────────────────────────────────────────────────
# Analysis — primary Sprint 2 endpoint
# ─────────────────────────────────────────────────────────────────────────────

class AnalyzeRequest(BaseModel):
    z_score: float | None = None   # Pre-computed Z-Score from Next.js Layer 1


@router.post("/analyze/user/{user_id}", tags=["analysis"])
def analyze_user(user_id: str, body: AnalyzeRequest = AnalyzeRequest()):
    """
    Run the full 3-layer detection engine for a single user.

    Optionally accepts a pre-computed z_score from the Next.js statistical
    baseline (Layer 1). Writes RiskSnapshot + Alert to Postgres.
    Returns the full threat assessment matching MLAnalysisResult interface.
    """
    if _ensemble is None:
        raise HTTPException(status_code=503, detail="ML models not loaded. POST /train first.")

    # ── Feature vector (Layer 2 + 3 input) ────────────────────────────────────
    try:
        fv = get_user_vector(user_id)
    except FileNotFoundError as e:
        raise HTTPException(
            status_code=422,
            detail=f"Normalized Parquet not found: {e}. Run ETL pipeline first."
        )

    # ── LSTM sequence (Layer 3 input, optional) ────────────────────────────────
    sequence = None
    if _ensemble.lstm_model.trained:
        try:
            daily_df = load_daily_snapshots()
            user_daily = daily_df[daily_df["user_id"] == user_id]
            if not user_daily.empty:
                seqs, _ = build_sequences_from_daily(user_daily)
                if len(seqs) > 0:
                    sequence = seqs[0]   # (30, 8)
        except Exception as e:
            logger.warning("Could not build LSTM sequence for %s: %s", user_id, e)

    # ── Run ensemble ──────────────────────────────────────────────────────────
    result = _ensemble.analyze_user(
        user_id=user_id,
        feature_vector=fv,
        sequence=sequence,
        z_score_external=body.z_score,
    )

    # ── SHAP explanation ───────────────────────────────────────────────────────
    if _explainer is not None:
        try:
            explanation = _explainer.explain(fv)
            result["contributing_features"] = explanation.get("top_features", [])
            result["explanation_summary"]   = explanation.get("summary", "")
        except Exception as e:
            logger.warning("SHAP explanation failed for %s: %s", user_id, e)

    # ── Write to Postgres ──────────────────────────────────────────────────────
    _persist_result(result)

    return result


@router.post("/analyze/batch", tags=["analysis"])
def analyze_batch(background_tasks: BackgroundTasks):
    """
    Trigger full-population analysis in the background.
    Returns immediately; check /model/status for completion.
    """
    if _ensemble is None:
        raise HTTPException(status_code=503, detail="ML models not loaded.")

    background_tasks.add_task(_run_batch)
    return {"status": "queued", "message": "Batch analysis started. Results written to Postgres."}


def _run_batch() -> None:
    """Background: analyze all users whose feature vectors are in Parquet."""
    logger.info("Batch analysis started…")
    try:
        X, user_ids = load_feature_matrix()
        seq_map: dict[str, "np.ndarray"] = {}

        if _ensemble.lstm_model.trained:
            try:
                daily_df = load_daily_snapshots()
                seqs, seq_uids = build_sequences_from_daily(daily_df)
                seq_map = dict(zip(seq_uids, seqs))
            except Exception as e:
                logger.warning("Could not load sequences for LSTM: %s", e)

        alerts_raised = 0
        for uid, fv in zip(user_ids, X):
            try:
                result = _ensemble.analyze_user(
                    uid, fv,
                    sequence=seq_map.get(uid),
                )
                if _explainer:
                    try:
                        expl = _explainer.explain(fv)
                        result["contributing_features"] = expl.get("top_features", [])
                    except Exception:
                        pass
                _persist_result(result)
                if result.get("is_anomaly"):
                    alerts_raised += 1
            except Exception as e:
                logger.warning("Batch: failed for user %s: %s", uid, e)

        logger.info("Batch complete. %d/%d users analyzed, %d alerts raised.",
                    len(user_ids), len(user_ids), alerts_raised)
    except Exception as e:
        logger.error("Batch analysis failed: %s", e)


def _persist_result(result: dict) -> None:
    """Write RiskSnapshot, update User, and conditionally create Alert."""
    # Build the full feature vector payload for lineage storage
    fv_payload: dict | None = None
    fv_list = result.get("feature_vector")
    if fv_list is not None:
        try:
            fv_payload = build_feature_payload(
                result["user_id"],
                np.array(fv_list, dtype=np.float32),
            )
        except Exception as e:
            logger.warning("Could not build feature payload for %s: %s", result.get("user_id"), e)

    try:
        write_risk_snapshot(
            user_id=result["user_id"],
            threat_score=result["threat_score"],
            z_score=result.get("z_score"),
            if_score=result.get("if_score"),
            lstm_score=result.get("lstm_score"),
            anomaly_flags=result.get("anomaly_flags", {}),
            contributing_features=result.get("contributing_features", []),
            model_version=result.get("model_version", "2.0.0"),
            alert_generated=result.get("is_anomaly", False),
            feature_vector=fv_payload,
        )
        update_user_risk(
            result["user_id"],
            result["threat_score"],
            result.get("is_anomaly", False),
        )
        write_user_snapshot(
            result["user_id"],
            result["threat_score"],
            result.get("if_score"),
            {
                "mlModel":    "Ensemble-v2",
                "zScore":     str(result.get("z_score") or "N/A"),
                "ifScore":    str(result.get("if_score") or "N/A"),
                "lstmScore":  str(result.get("lstm_score") or "N/A"),
                "threatScore": result["threat_score"],
                "isAnomaly":  result.get("is_anomaly", False),
            },
        )
        if result.get("is_anomaly"):
            create_alert_if_needed(
                result["user_id"],
                result["threat_score"],
                result.get("confidence", 0.7),
                result.get("contributing_features", []),
            )
    except Exception as e:
        # DB errors must not break the API response
        logger.error("Failed to persist result for user %s: %s", result.get("user_id"), e)


# ─────────────────────────────────────────────────────────────────────────────
# Explainability
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/explain/{user_id}", tags=["explainability"])
def explain_user(user_id: str):
    """Return SHAP explanation for a user's latest risk score."""
    if _explainer is None:
        raise HTTPException(status_code=503, detail="SHAP explainer not available.")

    try:
        fv = get_user_vector(user_id)
    except FileNotFoundError as e:
        raise HTTPException(status_code=422, detail=str(e))

    return {"user_id": user_id, "explanation": _explainer.explain(fv)}


# ─────────────────────────────────────────────────────────────────────────────
# Ingestion
# ─────────────────────────────────────────────────────────────────────────────

@router.post("/ingest/cert", tags=["ingestion"])
def ingest_cert():
    """Batch-load all CERT CSV files → normalised Parquet. Returns summary stats."""
    result = run_pipeline()
    return {"status": "ok", "summary": result}


# ─────────────────────────────────────────────────────────────────────────────
# Training
# ─────────────────────────────────────────────────────────────────────────────

@router.post("/train", tags=["training"])
def train_models(background_tasks: BackgroundTasks):
    """
    Train all 3 detection layers offline on CERT Parquet data.
    Runs in background — check /model/status for completion.
    """
    if _ensemble is None:
        raise HTTPException(status_code=503, detail="ML service not initialised.")
    background_tasks.add_task(_run_training)
    return {"status": "queued", "message": "Training started. Check /model/status."}


def _run_training() -> None:
    try:
        report = run_training()
        # Reload weights into the running ensemble after training
        _ensemble.load()
        logger.info("Training complete and weights reloaded: %s", report)
    except Exception as e:
        logger.error("Training failed: %s", e)


# ─────────────────────────────────────────────────────────────────────────────
# Model status & evaluation
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/model/status", tags=["meta"])
def model_status():
    if _ensemble is None:
        return {"status": "not_loaded"}
    status = _ensemble.status()

    report_path = Path(__file__).parent.parent / "models" / "weights" / "eval_report.json"
    if report_path.exists():
        with open(report_path) as f:
            status["latest_eval"] = json.load(f).get("default_threshold_metrics")

    return status


@router.post("/evaluate", tags=["meta"])
def trigger_evaluation(background_tasks: BackgroundTasks, from_db: bool = False):
    """Run precision/recall evaluation in background."""
    background_tasks.add_task(_run_eval, from_db)
    return {"status": "queued", "source": "postgres" if from_db else "parquet"}


def _run_eval(from_db: bool) -> None:
    try:
        report = run_evaluation(from_db=from_db)
        m = report["default_threshold_metrics"]
        logger.info(
            "Eval complete — ROC-AUC=%.3f  P=%.3f  R=%.3f  F1=%.3f  FPR=%.3f  FNR=%.3f",
            m.get("roc_auc") or 0, m["precision_malicious"], m["recall_malicious"],
            m["f1_malicious"], m["fpr"], m["fnr"],
        )
    except Exception as e:
        logger.error("Evaluation failed: %s", e)
