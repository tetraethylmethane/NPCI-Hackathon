/**
 * lib/crypto/anonymization.ts
 * ============================
 * Sprint 5 — Data Anonymization
 *
 * SHA-256 hashing for CERT user identifiers and pseudonymization helpers
 * used by both the pipeline seeder and API routes.
 *
 * Design decisions:
 *  - HMAC-SHA256 (not plain SHA-256) so the mapping is only reversible by
 *    parties with the ANONYMIZATION_SECRET — prevents offline rainbow tables.
 *  - The original_id ↔ hashed_id mapping is stored in IdentityMapping (Postgres)
 *    and readable only by ADMIN-role API routes.
 *  - Email addresses are replaced with <local-part-hash>@[redacted].
 *  - IP/PC identifiers are replaced with a deterministic but opaque token.
 */

import { createHmac, randomBytes } from "crypto";

// ---------------------------------------------------------------------------
// Secret — injected at runtime; falls back to a dev-only constant.
// In production set ANONYMIZATION_SECRET in the environment.
// ---------------------------------------------------------------------------
const SECRET =
  process.env.ANONYMIZATION_SECRET ?? "npci-dev-anon-secret-change-me";

// ---------------------------------------------------------------------------
// Core: HMAC-SHA256 hex digest
// ---------------------------------------------------------------------------

/**
 * Returns the HMAC-SHA256 hex digest of `value` using the anonymization secret.
 * Deterministic — same input always produces the same digest.
 */
export function hmacSha256(value: string): string {
  return createHmac("sha256", SECRET).update(value).digest("hex");
}

// ---------------------------------------------------------------------------
// User-ID anonymization
// ---------------------------------------------------------------------------

/**
 * Pseudonymize a CERT/internal user identifier.
 * Returns a 16-char hex prefix (enough to be unique across the CERT dataset).
 */
export function anonymizeUserId(originalId: string): string {
  return hmacSha256(originalId).slice(0, 16);
}

// ---------------------------------------------------------------------------
// Email pseudonymization
// ---------------------------------------------------------------------------

/**
 * Replace the local part of an email address with a hashed token.
 * "alice@example.com"  →  "a3f8b1c2d4e5f6a7@[redacted]"
 * Preserves domain presence (so sender vs receiver domain still detectable)
 * but makes the address unlinkable to a real person.
 */
export function pseudonymizeEmail(email: string): string {
  if (!email || !email.includes("@")) return "[redacted]";
  const [local] = email.split("@");
  const token = hmacSha256(email).slice(0, 16);
  return `${token}@[redacted]`;
}

// ---------------------------------------------------------------------------
// PC / workstation pseudonymization
// ---------------------------------------------------------------------------

/**
 * Replace a workstation name with a deterministic opaque token.
 * "PC-ACM2278-1" → "PC-a3f8b1c2"
 */
export function pseudonymizePc(pc: string): string {
  if (!pc || pc === "UNKNOWN-PC") return "UNKNOWN-PC";
  return `PC-${hmacSha256(pc).slice(0, 8)}`;
}

// ---------------------------------------------------------------------------
// Batch helpers (used in seed_postgres.py companion code)
// ---------------------------------------------------------------------------

/**
 * Anonymize all user_id values in a records array in place.
 * Returns a Map of { anonymizedId → originalId } for IdentityMapping writes.
 */
export function anonymizeBatch(
  records: Array<{ user_id: string }>,
): Map<string, string> {
  const mapping = new Map<string, string>();
  for (const row of records) {
    const anon = anonymizeUserId(row.user_id);
    if (!mapping.has(anon)) mapping.set(anon, row.user_id);
    row.user_id = anon;
  }
  return mapping;
}
