"""
NPCI PS3 — ML Microservice  (Sprint 2)
========================================
FastAPI service exposing the 3-layer Insider Threat Detection engine.

Endpoints (full docs at /docs):
  POST /analyze/user/{user_id}  — run full 3-layer analysis, write to Postgres
  POST /analyze/batch           — background full-population scan
  GET  /explain/{user_id}       — SHAP feature attribution
  POST /ingest/cert             — batch-load CERT CSV → Parquet
  POST /train                   — train all models on Parquet data (background)
  POST /evaluate                — precision/recall report (background)
  GET  /model/status            — readiness + latest eval metrics
  GET  /health                  — liveness probe
"""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from models.ensemble import EnsembleModel
from explainability.shap_explainer import SHAPExplainer
from api.routes import router as api_router, set_models

logger = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt="%H:%M:%S",
)

ensemble: EnsembleModel | None = None
explainer: SHAPExplainer | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global ensemble, explainer

    ensemble = EnsembleModel()
    ensemble.load()   # loads from models/weights/ — no-op if not trained yet

    if ensemble.rf_model.trained:
        explainer = SHAPExplainer(ensemble.rf_model)
        logger.info("SHAP explainer ready.")
    else:
        logger.warning("RF not trained — SHAP explanations unavailable until /train runs.")

    set_models(ensemble, explainer)
    logger.info("ML service ready.  IF=%s  RF=%s  LSTM=%s",
                "✓" if ensemble.if_model.trained   else "—",
                "✓" if ensemble.rf_model.trained   else "—",
                "✓" if ensemble.lstm_model.trained else "—")
    yield
    logger.info("ML service shutting down.")


app = FastAPI(
    title="NPCI Insider Threat Detection — ML Service",
    version="2.0.0",
    description="3-layer detection engine: Z-Score + Isolation Forest + LSTM Autoencoder",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

app.include_router(api_router)


@app.get("/health", tags=["meta"])
def health():
    return {
        "status": "ok",
        "isolation_forest": ensemble.if_model.trained   if ensemble else False,
        "random_forest":    ensemble.rf_model.trained   if ensemble else False,
        "lstm":             ensemble.lstm_model.trained if ensemble else False,
    }
