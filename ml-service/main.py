"""
NPCI PS3 — ML Microservice
FastAPI service exposing the Insider Threat Detection engine.

Endpoints:
  POST /analyze/batch          — run full analysis for all users
  POST /analyze/user/{user_id} — on-demand single-user analysis
  GET  /explain/{user_id}      — SHAP explanation for latest risk score
  POST /ingest/cert            — batch-load CERT dataset CSVs
  GET  /model/status           — model version + last trained timestamp
  GET  /health                 — liveness probe
"""

from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware

from pipeline.ingest import ingest_cert_dataset
from models.ensemble import EnsembleModel
from explainability.shap_explainer import SHAPExplainer
from api.routes import router as api_router


ensemble: EnsembleModel | None = None
explainer: SHAPExplainer | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Load models on startup."""
    global ensemble, explainer
    ensemble = EnsembleModel()
    ensemble.load()          # loads persisted weights from models/weights/
    explainer = SHAPExplainer(ensemble.rf_model)
    print("✅ ML models loaded and ready.")
    yield
    print("ML service shutting down.")


app = FastAPI(
    title="NPCI Insider Threat ML Service",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],  # Next.js dev server
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

app.include_router(api_router)


@app.get("/health")
def health():
    return {"status": "ok", "model_loaded": ensemble is not None}
