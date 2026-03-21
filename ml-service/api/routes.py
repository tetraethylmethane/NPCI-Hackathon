"""
FastAPI route definitions for the ML microservice.
"""

import os
import numpy as np
from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel

from pipeline.ingest import ingest_cert_dataset, load_logon, load_device, load_file, load_email, load_http, load_ground_truth
from pipeline.features import extract_features
from models.ensemble import EnsembleModel

router = APIRouter()

# Injected by main.py at startup
_ensemble: EnsembleModel | None = None
_explainer = None


def set_models(ensemble: EnsembleModel, explainer) -> None:
    global _ensemble, _explainer
    _ensemble = ensemble
    _explainer = explainer


# ---------------------------------------------------------------------------
# Ingestion
# ---------------------------------------------------------------------------

@router.post("/ingest/cert", tags=["ingestion"])
def ingest_cert():
    """Batch-load all CERT CSV files and return summary statistics."""
    result = ingest_cert_dataset()
    return {"status": "ok", "summary": result}


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------

class AnalyzeUserRequest(BaseModel):
    user_id: str


@router.post("/analyze/user/{user_id}", tags=["analysis"])
def analyze_user(user_id: str):
    """Run full ensemble analysis for a single user."""
    if _ensemble is None:
        raise HTTPException(status_code=503, detail="ML models not loaded")

    try:
        logon_df = load_logon()
        device_df = load_device()
        file_df = load_file()
        email_df = load_email()
        http_df = load_http()
    except FileNotFoundError as e:
        raise HTTPException(status_code=422, detail=f"Dataset file missing: {e}")

    fv = extract_features(user_id, logon_df, device_df, file_df, email_df, http_df)
    result = _ensemble.analyze_user(user_id, fv)

    if _explainer is not None:
        result["explanation"] = _explainer.explain(fv)

    return result


@router.post("/analyze/batch", tags=["analysis"])
async def analyze_batch(background_tasks: BackgroundTasks):
    """
    Trigger batch analysis for all users found in CERT dataset.
    Runs in background — returns immediately.
    """
    if _ensemble is None:
        raise HTTPException(status_code=503, detail="ML models not loaded")

    background_tasks.add_task(_run_batch_analysis)
    return {"status": "queued", "message": "Batch analysis started in background"}


def _run_batch_analysis():
    """Background task: analyze all users in CERT dataset."""
    try:
        logon_df = load_logon()
        all_users = logon_df["user_id"].unique()
        device_df = load_device()
        file_df = load_file()
        email_df = load_email()
        http_df = load_http()

        results = []
        for uid in all_users:
            fv = extract_features(uid, logon_df, device_df, file_df, email_df, http_df)
            result = _ensemble.analyze_user(uid, fv)
            results.append(result)

        print(f"✅ Batch complete: {len(results)} users analyzed.")
        return results
    except Exception as e:
        print(f"❌ Batch analysis failed: {e}")


# ---------------------------------------------------------------------------
# Explainability
# ---------------------------------------------------------------------------

@router.get("/explain/{user_id}", tags=["explainability"])
def explain_user(user_id: str):
    """Return SHAP explanation for the latest risk score of a user."""
    if _explainer is None:
        raise HTTPException(status_code=503, detail="Explainer not available")

    try:
        logon_df = load_logon()
        device_df = load_device()
        file_df = load_file()
        email_df = load_email()
        http_df = load_http()
    except FileNotFoundError as e:
        raise HTTPException(status_code=422, detail=f"Dataset file missing: {e}")

    fv = extract_features(user_id, logon_df, device_df, file_df, email_df, http_df)
    explanation = _explainer.explain(fv)
    return {"user_id": user_id, "explanation": explanation}


# ---------------------------------------------------------------------------
# Training
# ---------------------------------------------------------------------------

@router.post("/train", tags=["training"])
async def train_models(background_tasks: BackgroundTasks):
    """
    Train the full ensemble on all available CERT data.
    If ground-truth labels exist, RF supervised training is included.
    """
    if _ensemble is None:
        raise HTTPException(status_code=503, detail="ML models not loaded")

    background_tasks.add_task(_run_training)
    return {"status": "queued", "message": "Training started in background. Check /model/status for updates."}


def _run_training():
    try:
        logon_df = load_logon()
        device_df = load_device()
        file_df = load_file()
        email_df = load_email()
        http_df = load_http()
        gt_df = load_ground_truth()

        all_users = logon_df["user_id"].unique()
        X = np.array([
            extract_features(uid, logon_df, device_df, file_df, email_df, http_df)
            for uid in all_users
        ])

        y = None
        if not gt_df.empty:
            malicious = set(gt_df["user_id"].tolist())
            y = np.array([1 if uid in malicious else 0 for uid in all_users])

        result = _ensemble.train(X, y)
        print(f"Training complete: {result}")
    except Exception as e:
        print(f"Training failed: {e}")


# ---------------------------------------------------------------------------
# Model status
# ---------------------------------------------------------------------------

@router.get("/model/status", tags=["meta"])
def model_status():
    if _ensemble is None:
        return {"status": "not_loaded"}
    return _ensemble.status()
