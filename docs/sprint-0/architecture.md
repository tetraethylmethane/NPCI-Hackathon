# Sprint 0 — System Architecture
## NPCI PS3: AI-Powered Insider Threat Detection System

---

## 3-Layer Architecture

```
╔══════════════════════════════════════════════════════════════════════════════════╗
║  LAYER 1 — DATA PIPELINE                                                        ║
║                                                                                  ║
║  ┌─────────────────────┐    ┌──────────────────────┐    ┌──────────────────┐   ║
║  │  CMU CERT Dataset   │    │  Live Activity Feed  │    │  LDAP / Identity ║   ║
║  │  (Batch CSV files)  │    │  (Next.js /ingest)   │    │  (User Context)  ║   ║
║  │                     │    │                      │    │                  ║   ║
║  │ • logon.csv         │    │ • PROJECT_CREATED     │    │ • Department     ║   ║
║  │ • device.csv        │    │ • FILE_UPLOADED       │    │ • Role / Tenure  ║   ║
║  │ • file.csv          │    │ • FILE_DELETED        │    │ • Manager link   ║   ║
║  │ • email.csv         │    │ • MEMBER_JOINED       │    │ • Access tier    ║   ║
║  │ • http.csv          │    │ • ACCOUNT_LOCKOUT     │    │                  ║   ║
║  └──────────┬──────────┘    └──────────┬───────────┘    └────────┬─────────┘   ║
║             │                          │                          │             ║
║             └──────────────────────────▼──────────────────────────┘             ║
║                              ┌─────────────────────┐                            ║
║                              │  Python Ingestion   │                            ║
║                              │  ml-service/        │                            ║
║                              │  pipeline/ingest.py │                            ║
║                              │                     │                            ║
║                              │ • Schema validation │                            ║
║                              │ • Dedup & normalise │                            ║
║                              │ • Timestamp align   │                            ║
║                              └──────────┬──────────┘                            ║
║                                         │                                        ║
║                              ┌──────────▼──────────┐                            ║
║                              │  Feature Engineering│                            ║
║                              │  pipeline/          │                            ║
║                              │  features.py        │                            ║
║                              │                     │                            ║
║                              │ Logon features:     │                            ║
║                              │  after_hours_ratio  │                            ║
║                              │  failed_login_count │                            ║
║                              │  unique_host_count  │                            ║
║                              │                     │                            ║
║                              │ Device features:    │                            ║
║                              │  usb_mount_count    │                            ║
║                              │  bulk_copy_flag     │                            ║
║                              │                     │                            ║
║                              │ File features:      │                            ║
║                              │  delete_ratio       │                            ║
║                              │  sensitive_access   │                            ║
║                              │                     │                            ║
║                              │ Email features:     │                            ║
║                              │  external_recip_ratio│                           ║
║                              │  large_attach_count │                            ║
║                              │                     │                            ║
║                              │ HTTP features:      │                            ║
║                              │  cloud_storage_hits │                            ║
║                              │  non_work_domain_r  │                            ║
║                              └──────────┬──────────┘                            ║
║                                         │ Feature Vector [f1..f20]              ║
╚═════════════════════════════════════════╪════════════════════════════════════════╝
                                          │
╔═════════════════════════════════════════╪════════════════════════════════════════╗
║  LAYER 2 — ML ENGINE (FastAPI)          │                                        ║
║                                         ▼                                        ║
║                              ┌──────────────────────┐                           ║
║                              │  Ensemble Model      │                           ║
║                              │  models/ensemble.py  │                           ║
║                              │                      │                           ║
║                              │  ┌────────────────┐  │                           ║
║                              │  │Isolation Forest│  │  ← primary unsupervised  ║
║                              │  │  (anomaly det) │  │                           ║
║                              │  └───────┬────────┘  │                           ║
║                              │          │            │                           ║
║                              │  ┌───────▼────────┐  │                           ║
║                              │  │ Random Forest  │  │  ← supervised (labeled)  ║
║                              │  │  (classifier)  │  │                           ║
║                              │  └───────┬────────┘  │                           ║
║                              │          │            │                           ║
║                              │  ┌───────▼────────┐  │                           ║
║                              │  │  Z-Score Stat  │  │  ← existing baseline     ║
║                              │  │  (fallback)    │  │                           ║
║                              │  └───────┬────────┘  │                           ║
║                              │          │            │                           ║
║                              │  ┌───────▼────────┐  │                           ║
║                              │  │ Score Fusion   │  │                           ║
║                              │  │ (weighted avg) │  │                           ║
║                              │  └───────┬────────┘  │                           ║
║                              └──────────┼────────────┘                          ║
║                                         │ Risk Score [0–100] + Confidence       ║
║                              ┌──────────▼──────────┐                            ║
║                              │  SHAP Explainability│                            ║
║                              │  explainability/    │                            ║
║                              │  shap_explainer.py  │                            ║
║                              │                     │                            ║
║                              │ • Top-3 risk drivers│                            ║
║                              │ • Feature importances│                           ║
║                              │ • Human-readable    │                            ║
║                              │   reason text       │                            ║
║                              └──────────┬──────────┘                            ║
║                                         │                                        ║
║             ┌───────────────────────────┼───────────────────────────┐           ║
║             ▼                           ▼                           ▼           ║
║   ┌──────────────────┐      ┌──────────────────┐      ┌──────────────────────┐ ║
║   │  Neon Postgres   │      │  Risk Alert      │      │  Model Registry      │ ║
║   │  (shared DB)     │      │  (threshold >70) │      │  (versioned weights) │ ║
║   │                  │      │                  │      │                      │ ║
║   │ • User.riskScore │      │ • CRITICAL  ≥ 90 │      │ • IsolationForest    │ ║
║   │ • UserSnapshot   │      │ • HIGH      ≥ 70 │      │   v1, v2 ...         │ ║
║   │ • ActivityLog    │      │ • MEDIUM    ≥ 40 │      │ • Retrain schedule   │ ║
║   │ • Alert table    │      │ • LOW        < 40│      │ • Eval metrics       │ ║
║   └──────────────────┘      └──────────┬───────┘      └──────────────────────┘ ║
║                                         │                                        ║
╚═════════════════════════════════════════╪════════════════════════════════════════╝
                                          │
╔═════════════════════════════════════════╪════════════════════════════════════════╗
║  LAYER 3 — DASHBOARD (Next.js)          │                                        ║
║                                         ▼                                        ║
║             ┌───────────────────────────────────────────────────┐               ║
║             │              SSE / WebSocket Gateway              │               ║
║             │     app/api/alerts/stream/route.ts                │               ║
║             │     (reads from Postgres NOTIFY or polling)       │               ║
║             └──────────────────────┬────────────────────────────┘               ║
║                                    │                                             ║
║        ┌───────────────────────────┼───────────────────────────────┐            ║
║        ▼                           ▼                               ▼            ║
║  ┌───────────────┐      ┌──────────────────────┐      ┌────────────────────┐   ║
║  │ Command Center│      │  User Risk Profile   │      │  Alert Queue       │   ║
║  │ (existing     │      │  • Risk trend chart  │      │  • Live alert feed │   ║
║  │  dashboard    │      │  • SHAP explanation  │      │  • Severity badge  │   ║
║  │  page.tsx)    │      │  • Activity timeline │      │  • Assign / Ack    │   ║
║  │               │      │  • Confidence score  │      │  • Escalate        │   ║
║  │ Extend with:  │      │  • Feature breakdown │      │                    │   ║
║  │ • Alert count │      │                      │      │ NEW COMPONENT      │   ║
║  │ • Model status│      │ EXTEND existing      │      │ AlertFeed.tsx      │   ║
║  └───────────────┘      │ UserTimeline.tsx      │      └────────────────────┘   ║
║                         └──────────────────────┘                                ║
║                                                                                  ║
║  ┌───────────────────────────────────────────────────────────────────────────┐  ║
║  │                     Investigator Workflow Panel                           │  ║
║  │  • Assign alert to analyst   • Mark as FP / TP   • Escalation history   │  ║
║  │  NEW: app/(dashboard)/investigations/page.tsx                             │  ║
║  └───────────────────────────────────────────────────────────────────────────┘  ║
╚══════════════════════════════════════════════════════════════════════════════════╝
```

---

## Service Communication Map

```
Next.js (port 3000)
    │
    ├── POST /api/ingest          → writes ActivityLog to Postgres
    ├── POST /api/admin/trigger-audit → calls FastAPI POST /analyze/batch
    ├── GET  /api/alerts/stream   → SSE, polls Alert table in Postgres
    └── GET  /api/users/[id]/explain → proxies FastAPI GET /explain/{user_id}

FastAPI ML Service (port 8000)
    │
    ├── POST /analyze/batch       ← called by Next.js trigger-audit
    ├── POST /analyze/user/{id}   ← single-user on-demand
    ├── GET  /explain/{user_id}   ← SHAP explanation JSON
    ├── POST /ingest/cert         ← batch CERT dataset loader
    ├── GET  /model/status        ← model version + last trained
    └── GET  /health

Shared Postgres (Neon)
    ├── Read by: FastAPI (user history, activity logs)
    └── Write by: FastAPI (riskScore, UserSnapshot, Alert)
         Next.js (ActivityLog ingestion, user status)
```

---

## Key Design Decisions

| Decision | Choice | Rationale |
|---|---|---|
| ML runtime | Python/FastAPI | scikit-learn, SHAP, joblib ecosystem; not available in Node |
| Integration | HTTP (Next.js → FastAPI) | Simplest; both share Postgres, no message broker needed for MVP |
| Streaming | SSE (Server-Sent Events) | Unidirectional alerts to browser; simpler than WebSockets for this use case |
| Primary ML model | Isolation Forest | Unsupervised; no labels needed; proven on CERT dataset in literature |
| Secondary model | Random Forest | CERT r4.2 includes ground-truth labels — enables supervised evaluation |
| Explainability | SHAP TreeExplainer | Exact SHAP for tree models; fast; human-readable feature attribution |
| Feature store | Postgres (UserSnapshot.vectorData) | Already exists; avoids Redis dependency for MVP |
| Existing Z-Score | Keep as fallback | Activates when ML service is unavailable; ensures dashboard never shows stale data |
