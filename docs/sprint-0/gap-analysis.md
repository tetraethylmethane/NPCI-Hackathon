# Sprint 0 — Gap Analysis
## Existing System vs NPCI PS3 Requirements

---

## Summary

| Area | Existing | NPCI Requirement | Status |
|---|---|---|---|
| Behavioral detection | Z-Score on UserSnapshot history | Multi-model ensemble (Isolation Forest + RF) | **EXTEND** |
| Data ingestion | Manual `POST /api/ingest` (4 event types) | CMU CERT dataset (5 CSV sources, 1000s of users) | **BUILD** |
| Feature engineering | `logs.length` + DELETE count (2 features) | Multi-source feature vector (20+ features) | **BUILD** |
| ML explainability | None (Z-score printed to console) | SHAP feature attribution per alert | **BUILD** |
| Real-time alerting | None (nightly cron only) | Live alert feed with severity tiers | **BUILD** |
| Alert workflow | Kill switch (LOCK/UNLOCK only) | Assign → Acknowledge → Escalate → Resolve | **BUILD** |
| Confidence scoring | None | Model confidence % per detection | **BUILD** |
| Dashboard streaming | None (full page reload) | SSE stream for live risk updates | **BUILD** |
| Python ML runtime | None (Node.js only) | FastAPI microservice | **BUILD** |
| CERT dataset processing | `dataset/email.csv` exists but unused | All 5 log sources ingested + ground truth | **BUILD** |
| pgvector usage | Schema has extension; unused | Embedding-based similarity search | **EXTEND** |
| Model versioning | None | Versioned models with eval metrics | **BUILD** |
| Audit trail | ActivityLog (append-only) | Immutable audit log with metadata JSON | **KEEP** |
| Account kill switch | `handleSecurityAction` LOCK/UNLOCK | Same behavior, extended to feed alerts | **KEEP** |

---

## Detailed Gap Analysis

### 1. Data Ingestion — REPLACE current manual approach for CERT data

**What exists:**
```typescript
// app/api/ingest/route.ts
const logSchema = z.object({
  userId: z.string(),
  projectId: z.string(),
  action: z.enum(["PROJECT_CREATED", "FILE_UPLOADED", "FILE_DELETED", "MEMBER_JOINED"]),
  description: z.string(),
});
```
- 4 hardcoded event types
- Requires a `projectId` (makes no sense for auth/device events)
- No batch processing
- No schema for logon, device, HTTP, or email events from CERT

**What NPCI requires:**
- Python batch loader that reads all 5 CERT CSVs (`logon`, `device`, `file`, `email`, `http`)
- Schema normalization: unify timestamps, user IDs across sources
- Deduplication and data quality checks
- Streaming path for real-time event ingestion
- `ActivityType` enum must be extended for CERT event types

**Action:** Build `ml-service/pipeline/ingest.py`. Extend `ActivityType` enum in Prisma schema.

---

### 2. Feature Engineering — BUILD from scratch

**What exists:**
```typescript
// lib/analysis.ts — entire "feature extraction"
const currentRisk = (logs.length * 1) + (logs.filter(l => l.action.includes("DELETE")).length * 25);
```
- 2 features: log count and DELETE event count
- No temporal analysis (after-hours, weekend patterns)
- No cross-source correlation (file + email + device)
- No baseline comparison per feature dimension

**What NPCI requires (CERT-aligned feature set):**

| Feature Group | Features |
|---|---|
| Logon | `after_hours_logon_ratio`, `weekend_logon_ratio`, `failed_login_count`, `unique_host_count`, `avg_session_duration_mins` |
| Device | `usb_mount_count`, `unique_device_count`, `bulk_file_copy_flag`, `device_after_hours` |
| File | `sensitive_file_access_count`, `file_delete_ratio`, `executable_download_count`, `bulk_access_flag` |
| Email | `external_recipient_ratio`, `large_attachment_count`, `after_hours_email_ratio`, `bcc_usage_count` |
| HTTP | `cloud_storage_visit_count`, `non_work_domain_ratio`, `job_site_visits`, `after_hours_browse_ratio` |

**Action:** Build `ml-service/pipeline/features.py` with `extract_features(user_id, window_days=30) -> np.ndarray`.

---

### 3. ML Model — EXTEND with Isolation Forest + Random Forest

**What exists:**
```typescript
// lib/analysis.ts
const finalScoreZ = zScore(currentRisk, avgScore, stdDev);
const isAnomaly = finalScoreZ > 2.0;
```
- Single-variable Z-Score
- No model training or persistence
- No confidence interval
- No ground truth evaluation

**What NPCI requires:**
- **Isolation Forest** — unsupervised anomaly detection on full 20-feature vector. Produces `anomaly_score ∈ [-1, 0]` mapped to `[0, 100]` risk scale.
- **Random Forest Classifier** — supervised, trained on CERT r4.2 ground truth labels (malicious users identified). Produces `malicious_probability ∈ [0, 1]`.
- **Ensemble fusion** — weighted combination: `risk = 0.6 × iso_score + 0.4 × rf_score` (weights tunable).
- Existing Z-Score retained as lightweight fallback (runs in Next.js when ML service is down).

**Action:** Build `ml-service/models/isolation_forest.py`, `ml-service/models/random_forest.py`, `ml-service/models/ensemble.py`.

---

### 4. Explainability — BUILD (does not exist)

**What exists:** `console.log(Z-Score printed to server terminal)` — not visible to dashboard users.

**What NPCI requires:**
- SHAP `TreeExplainer` applied to Random Forest predictions
- Top 3 features driving the risk score, with direction (↑ increases risk / ↓ decreases)
- Human-readable strings: e.g., _"User accessed 3 sensitive files after hours (3.2× above baseline)"_
- Stored in `UserSnapshot.vectorData` JSON for display in dashboard

**Action:** Build `ml-service/explainability/shap_explainer.py`. Extend `UserSnapshot.vectorData` JSON shape. Update `UserTimeline.tsx` to display explanations.

---

### 5. Real-Time Alerting — BUILD (does not exist)

**What exists:** Nightly cron at 00:00 + manual `/api/admin/trigger-audit` button. No alert table, no severity tiers, no live feed.

**What NPCI requires:**
- `Alert` Prisma model (see schema additions below)
- Severity tiers: CRITICAL (≥90), HIGH (≥70), MEDIUM (≥40), LOW (<40)
- SSE endpoint `GET /api/alerts/stream` — streams new alerts to dashboard in real time
- Alert card component `AlertFeed.tsx` in dashboard
- Alert throttle: max 1 alert per user per 15-minute window to prevent flooding

**Prisma additions needed:**
```prisma
model Alert {
  id          String      @id @default(cuid())
  userId      String
  riskScore   Int
  severity    AlertSeverity
  explanation Json        // SHAP top features
  status      AlertStatus @default(OPEN)
  assignedTo  String?
  resolvedAt  DateTime?
  createdAt   DateTime    @default(now())
  user        User        @relation(...)
}

enum AlertSeverity { CRITICAL HIGH MEDIUM LOW }
enum AlertStatus   { OPEN ASSIGNED ACKNOWLEDGED RESOLVED FALSE_POSITIVE }
```

**Action:** Add `Alert` model to `prisma/schema.prisma`. Build `app/api/alerts/stream/route.ts`. Build `components/AlertFeed.tsx`.

---

### 6. Investigator Workflow — BUILD (does not exist)

**What exists:** Binary LOCK/UNLOCK via `handleSecurityAction`. No case management.

**What NPCI requires:**
- Alert state machine: `OPEN → ASSIGNED → ACKNOWLEDGED → RESOLVED | FALSE_POSITIVE`
- Server action `assignAlert(alertId, analystId)`
- Server action `resolveAlert(alertId, resolution: "TP" | "FP", notes: string)`
- New dashboard page: `app/(dashboard)/investigations/page.tsx`

**Action:** Add to `lib/actions/security.ts`. Add new page under `(dashboard)`.

---

### 7. ActivityType Enum — EXTEND

**What exists:**
```prisma
enum ActivityType {
  PROJECT_CREATED, PROJECT_UPDATED, FILE_UPLOADED, FILE_DELETED,
  MEMBER_JOINED, MEMBER_LEFT, ACCOUNT_LOCKOUT, ACCOUNT_RECOVERY, ...
}
```

**What must be added for CERT alignment:**
```prisma
// CERT DATASET EVENT TYPES
LOGON_SUCCESS
LOGON_FAILURE
LOGOFF
USB_DEVICE_CONNECTED
USB_FILE_COPY
HTTP_VISIT
EMAIL_SENT
EMAIL_RECEIVED
```

**Action:** Add to `prisma/schema.prisma` under `ActivityType`.

---

### 8. What to Keep Without Changes

| Component | Why Keep |
|---|---|
| `lib/cron.ts` | Nightly baselining — extend to call FastAPI instead of local Z-Score |
| `lib/actions/security.ts` | LOCK/UNLOCK works correctly; extend with alert state transitions |
| `ActivityLog` model | Append-only audit trail is correct; just extend ActivityType enum |
| `UserSnapshot` model | Time-series snapshots work; extend `vectorData` JSON shape |
| `components/RiskTrendChart.tsx` | Reuse for risk score over time visualization |
| `app/(dashboard)/layout.tsx` | Navigation structure is correct; add "Investigations" link |
| `/api/admin/trigger-audit` | Keep; rewire to call FastAPI instead of local `vectorizeUserBehavior` |

---

## Sprint Sequencing (Recommended)

| Sprint | Focus |
|---|---|
| **Sprint 0** | Architecture + gap analysis + repo structure (this document) |
| **Sprint 1** | CERT ingestion pipeline + feature engineering (Python) |
| **Sprint 2** | Isolation Forest + Random Forest models + SHAP explainability |
| **Sprint 3** | FastAPI service + integration with Next.js (replace Z-Score calls) |
| **Sprint 4** | Real-time alert SSE stream + AlertFeed dashboard component |
| **Sprint 5** | Investigator workflow + case management page + demo polish |
