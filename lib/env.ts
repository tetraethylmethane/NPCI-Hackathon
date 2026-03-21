/** Shared runtime constants used by ML analysis routes. */
export const ML_SERVICE_URL  = process.env.ML_SERVICE_URL ?? "http://localhost:8000";
export const ALERT_THRESHOLD = 70;    // threat_score >= this → generate Alert
export const Z_THRESHOLD     = 2.5;   // Z > this → statistical anomaly
export const WINDOW_DAYS     = 30;    // rolling history window (days / snapshots)
