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

No test suite is configured. There is no `npm test` command.

## Architecture Overview

**NPCI Identity Guard** is an AI-powered insider threat detection system for NPCI PS3, built on the CMU CERT Insider Threat Dataset. It is a **3-layer system**:

```
Data Pipeline (Python)  →  ML Engine (FastAPI)  →  Dashboard (Next.js)
```

See [docs/sprint-0/architecture.md](docs/sprint-0/architecture.md) for the full architecture diagram.

### Layer 1 — Data Pipeline (`ml-service/pipeline/`)
- `ingest.py` — loads all 5 CERT CSV sources (`logon`, `device`, `file`, `email`, `http`) and normalises timestamps/columns
- `features.py` — extracts a **20-dimensional feature vector** per user (5 logon + 4 device + 5 file + 4 email + 2 HTTP features). `FEATURE_NAMES` list is the canonical reference for feature ordering.

### Layer 2 — ML Engine (`ml-service/`)
- **Isolation Forest** (`models/isolation_forest.py`) — unsupervised primary model; no labels needed
- **Random Forest** (`models/random_forest.py`) — supervised; trained when CERT ground-truth labels exist (`dataset/answers/insiders.csv`)
- **Ensemble** (`models/ensemble.py`) — fuses both scores: `risk = 0.6×IF + 0.4×RF`. Severity tiers: CRITICAL ≥90, HIGH ≥70, MEDIUM ≥40, LOW <40
- **SHAP Explainer** (`explainability/shap_explainer.py`) — top-3 feature attributions per prediction, stored in `UserSnapshot.vectorData`
- **FastAPI routes** (`api/routes.py`) — `POST /analyze/batch`, `POST /analyze/user/{id}`, `GET /explain/{id}`, `POST /train`, `GET /model/status`
- Trained weights persisted to `ml-service/models/weights/` via `joblib`

### Layer 3 — Dashboard (Next.js, existing + extensions)

**Existing (keep):**
- `lib/analysis.ts` — Z-Score engine; retained as fallback when ML service is unreachable
- `lib/cron.ts` — nightly job at 00:00; will be rewired to call `POST /analyze/batch` on FastAPI
- `lib/actions/security.ts` — LOCK/UNLOCK server actions
- `app/(dashboard)/page.tsx` — main command center
- `components/RiskTrendChart.tsx`, `components/UserTimeline.tsx`

**To build (Sprint 5+):**
- `app/api/alerts/stream/route.ts` — SSE endpoint streaming new `Alert` rows to dashboard
- `components/AlertFeed.tsx` — live alert feed component
- `app/(dashboard)/investigations/page.tsx` — alert assignment + resolution workflow

### Data Model Key Points

The Prisma schema has four concern areas:

1. **Security/Fraud**: `User` (`riskScore`, `isFlagged`, `status`), `UserSnapshot`, `ActivityLog`, `Alert` (Sprint 5)
2. **Collaboration Workspace**: `Project`, `UserOnProject`, `Task`, `Commit`, `Meeting`, `ProjectFile`
3. **Public Marketplace**: `ProjectPost`, `ProjectApplication`, `Company`, `ProjectSeeker`
4. **Supporting**: `FinancialMetrics`, `MembershipSubscription`, `Blog`, `Resource`

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
| 5 | Investigator workflow + demo | `app/(dashboard)/investigations/` |
