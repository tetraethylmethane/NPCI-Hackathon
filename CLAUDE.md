# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

### Next.js (frontend + API)
```bash
npm run dev      # Start development server (port 3000)
npm run build    # Production build
npm start        # Start production server
npm run lint     # Run ESLint
```

### Python ML service
```bash
cd ml-service
pip install -r requirements.txt
uvicorn main:app --reload --port 8000   # Dev server (port 8000)
```

### Docker (ML service only)
```bash
docker-compose up ml-service            # Build and run ML service
docker-compose up ml-service --build    # Force rebuild
```

### Database (Prisma)
```bash
npx prisma generate          # Regenerate client after schema changes
npx prisma migrate dev       # Apply migrations in development
npx prisma db push           # Push schema without migration file
npx prisma studio            # DB GUI
```

### Utility scripts
```bash
npx ts-node scripts/seed-ml.ts         # Seed ML snapshots
npx ts-node scripts/verifysprint3.ts   # Verify Sprint 3 integration
```

No test suite is configured. There is no `npm test` command.

## Environment Variables

No `.env` is checked in. Required vars:
- `DATABASE_URL` — PostgreSQL connection string (Neon)
- `ML_SERVICE_URL` — defaults to `http://localhost:8000` if unset (see `lib/env.ts`)
- `ANONYMIZATION_SECRET` — HMAC key for user-ID pseudonymization (Python + TS must share this value)
- `FIELD_ENCRYPTION_KEY` — 64-char hex AES-256 key for `lastLocation` column encryption (`lib/crypto/fieldEncryption.ts`)
- `SESSION_SECRET` — HMAC key for signing `npci_session` cookies (`lib/auth/rbac.ts`)
- `DEMO_MODE=true` — enable `/api/auth/demo-login` endpoint for evaluators (disable in production)

Constants exported from `lib/env.ts`: `ML_SERVICE_URL`, `ALERT_THRESHOLD` (70), `Z_THRESHOLD` (2.5), `WINDOW_DAYS` (30).

## Architecture Overview

**NPCI Identity Guard** is an AI-powered insider threat detection system for NPCI PS3, built on the CMU CERT Insider Threat Dataset. It is a **3-layer system**:

```
Data Pipeline (Python)  →  ML Engine (FastAPI)  →  Dashboard (Next.js)
```

See [docs/sprint-0/architecture.md](docs/sprint-0/architecture.md) for the full architecture diagram and [docs/sprint-0/gap-analysis.md](docs/sprint-0/gap-analysis.md) for requirement-vs-implementation mapping.

### Layer 1 — Data Pipeline (`ml-service/pipeline/`)
- `ingest.py` — loads all 5 CERT CSV sources (`logon`, `device`, `file`, `email`, `http`), normalises timestamps/columns, **then pseudonymizes** via `anonymize.py` before writing Parquet
- `anonymize.py` — Sprint 5: HMAC-SHA256 pseudonymization of `user_id`, `pc`, email addresses, URLs; returns `IdentityMapping` records to be written to Postgres
- `features.py` — extracts a **20-dimensional feature vector** per user (5 logon + 4 device + 5 file + 4 email + 2 HTTP features). `FEATURE_NAMES` list is the canonical reference for feature ordering.
- `transform.py`, `peer_groups.py` — data transformation and peer-group baselining
- `run_etl.py` — orchestrates full ETL; `seed_postgres.py` — writes processed data to Postgres
- `constants.py` — shared pipeline constants

### Layer 2 — ML Engine (`ml-service/`)
- **Isolation Forest** (`models/isolation_forest.py`) — unsupervised primary model; no labels needed
- **Random Forest** (`models/random_forest.py`) — supervised; trained when CERT ground-truth labels exist (`dataset/answers/insiders.csv`)
- **LSTM Autoencoder** (`models/lstm_autoencoder.py`) — optional third model; loaded at startup if weights present
- **Ensemble** (`models/ensemble.py`) — fuses both scores: `risk = 0.6×IF + 0.4×RF`. Severity tiers: CRITICAL ≥90, HIGH ≥70, MEDIUM ≥40, LOW <40
- **SHAP Explainer** (`explainability/shap_explainer.py`) — top-3 feature attributions per prediction, stored in `UserSnapshot.vectorData`
- **Trainer** (`models/trainer.py`) — training pipeline for all models
- **DB writes** (`db.py`) — writes `RiskSnapshot`, updates `User.riskScore`, creates `Alert` rows directly from Python
- **Evaluation** (`evaluation/eval_metrics.py`) — precision/recall against CERT ground-truth labels
- Trained weights persisted to `ml-service/models/weights/` via `joblib`

**FastAPI routes** (`api/routes.py`) — all background tasks use FastAPI `BackgroundTasks`:
- `POST /analyze/user/{user_id}` — full 3-layer analysis; accepts optional pre-computed Z-score
- `POST /analyze/batch` — full-population scan (background)
- `GET /explain/{user_id}` — SHAP feature attribution
- `POST /ingest/cert` — load CERT CSVs → Parquet
- `POST /train` — train all models (background)
- `POST /evaluate` — precision/recall evaluation (background)
- `GET /model/status` — model readiness + eval metrics
- `GET /health` — liveness check

Models are loaded at startup via FastAPI lifespan; CORS is configured for `http://localhost:3000`.

### Layer 3 — Dashboard (Next.js)

**Existing:**
- `lib/analysis.ts` — tries FastAPI `/analyze/user/{id}` first; falls back to Z-Score if service unreachable
- `lib/cron.ts` — nightly job at 00:00; calls `POST /analyze/batch` on FastAPI
- `lib/actions/security.ts` — LOCK/UNLOCK server actions (Sprint 5: ADMIN-only role guard + `createAuditEntry`)
- `lib/simulate.ts` — event simulation helpers
- `lib/audit.ts` — Sprint 5: `createAuditEntry()` helper + Prisma extension enforcing append-only on `ActivityLog`
- `lib/auth/rbac.ts` — Sprint 5: `SecurityRole` type, `PERMISSIONS` map, `can()`, signed session cookie encode/decode
- `lib/crypto/anonymization.ts` — Sprint 5: HMAC-SHA256 user-ID and email pseudonymization (Node.js)
- `lib/crypto/fieldEncryption.ts` — Sprint 5: AES-256-GCM encrypt/decrypt for `lastLocation` and other sensitive columns
- `middleware.ts` — Sprint 5: Next.js Edge middleware enforcing RBAC on all matched routes
- `app/(dashboard)/page.tsx` — main command center
- `app/api/ml/analyze/route.ts` — Next.js proxy to FastAPI for on-demand user analysis
- `app/api/admin/trigger-audit/route.ts` — manually triggers batch analysis
- `app/api/admin/testbrain/route.ts` — tests ML service connectivity
- `app/api/ingest/route.ts` — manual activity log ingestion
- `components/RiskTrendChart.tsx`, `components/UserTimeline.tsx`

**To build (Sprint 4+):**
- `app/api/alerts/stream/route.ts` — SSE endpoint streaming new `Alert` rows to dashboard
- `components/AlertFeed.tsx` — live alert feed component
- `app/(dashboard)/investigations/page.tsx` — alert assignment + resolution workflow

### Data Model Key Points

The Prisma schema has four concern areas:

1. **Security/Fraud**: `User` (`riskScore`, `isFlagged`, `status`, `securityRole`), `UserSnapshot`, `ActivityLog`, `Alert`, `IdentityMapping` (Sprint 5)
2. **Collaboration Workspace**: `Project`, `UserOnProject`, `Task`, `Commit`, `Meeting`, `ProjectFile`
3. **Public Marketplace**: `ProjectPost`, `ProjectApplication`, `Company`, `ProjectSeeker`
4. **Supporting**: `FinancialMetrics`, `MembershipSubscription`, `Blog`, `Resource`

Sprint 5 additions to schema:
- `User.securityRole: SecurityRole` (`ADMIN` | `ANALYST` | `VIEWER`, default `VIEWER`) — dashboard RBAC
- `IdentityMapping` — stores SHA-256(CERT user_id) → original_id; ADMIN-only via `/api/admin/audit-log`
- `pgcrypto` extension enabled in datasource for future Postgres-side encryption functions

`UserSnapshot.vectorData` JSON shape (after ML integration):
```json
{ "mlModel": "Ensemble", "ifScore": 62.1, "rfProba": 0.71, "featureVector": [...],
  "topFeatures": [...], "explanation": "...", "timestamp": "..." }
```

`Alert.explanation` stores the SHAP `top_features` array from `shap_explainer.py`.

### Path Aliases

`@/*` maps to the project root (`tsconfig.json`). Use `@/lib/...`, `@/components/...` for all Next.js imports.

### UI Stack

- **Tailwind CSS 4** for styling
- **shadcn/ui** in `components/ui/` (Radix Nova style, `cn()` from `lib/utils.ts`)
- **Recharts** for charts
- **Lucide React** for icons

## Sprint Planning

| Sprint | Goal | Docs |
|---|---|---|
| 0 | Architecture + gap analysis + repo structure | [docs/sprint-0/](docs/sprint-0/) |
| 1 | CERT ingestion + feature engineering | `ml-service/pipeline/` |
| 2 | Isolation Forest + RF + SHAP | `ml-service/models/` |
| 3 | FastAPI integration with Next.js | Replace Z-Score calls |
| 4 | Real-time SSE alert stream | `app/api/alerts/stream/` |
| 5 | Privacy, Security & Compliance | `lib/crypto/`, `lib/auth/`, `middleware.ts`, `ml-service/pipeline/anonymize.py` |
