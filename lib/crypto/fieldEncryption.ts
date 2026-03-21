/**
 * lib/crypto/fieldEncryption.ts
 * ==============================
 * Sprint 5 — Application-Level Field Encryption (AES-256-GCM)
 *
 * Encrypts sensitive Postgres columns (lastLocation, email metadata) at the
 * application layer using Node.js built-in `crypto`. No external dependency.
 *
 * Wire format (base64url):
 *   <12-byte IV> || <ciphertext> || <16-byte auth tag>
 *   All concatenated then base64url-encoded as a single string.
 *
 * Key material:
 *   Set FIELD_ENCRYPTION_KEY to a 32-byte hex string (64 hex chars).
 *   Generate once with:  node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
 *   Falls back to a deterministic dev-only key — CHANGE IN PRODUCTION.
 */

import { createCipheriv, createDecipheriv, randomBytes } from "crypto";

// ---------------------------------------------------------------------------
// Key derivation
// ---------------------------------------------------------------------------

const HEX_KEY =
  process.env.FIELD_ENCRYPTION_KEY ??
  "0000000000000000000000000000000000000000000000000000000000000000"; // dev fallback

function getKey(): Buffer {
  if (HEX_KEY.length !== 64) {
    throw new Error(
      "FIELD_ENCRYPTION_KEY must be a 64-character hex string (32 bytes).",
    );
  }
  return Buffer.from(HEX_KEY, "hex");
}

// ---------------------------------------------------------------------------
// Encrypt
// ---------------------------------------------------------------------------

/**
 * Encrypt a plaintext string with AES-256-GCM.
 * Returns a base64url-encoded string safe for storage in any text column.
 * Returns null if plaintext is null/undefined.
 */
export function encryptField(plaintext: string | null | undefined): string | null {
  if (plaintext == null) return null;
  const key = getKey();
  const iv = randomBytes(12); // 96-bit nonce for GCM
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const encrypted = Buffer.concat([
    cipher.update(plaintext, "utf8"),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag(); // 16 bytes
  // Concatenate: iv (12) || ciphertext || tag (16)
  const payload = Buffer.concat([iv, encrypted, tag]);
  return payload.toString("base64url");
}

// ---------------------------------------------------------------------------
// Decrypt
// ---------------------------------------------------------------------------

/**
 * Decrypt a value produced by encryptField().
 * Returns the original plaintext, or null if input is null/undefined.
 * Throws on authentication failure (tampered ciphertext).
 */
export function decryptField(ciphertext: string | null | undefined): string | null {
  if (ciphertext == null) return null;
  const key = getKey();
  const payload = Buffer.from(ciphertext, "base64url");
  if (payload.length < 28) throw new Error("Ciphertext too short — corrupted.");
  const iv = payload.subarray(0, 12);
  const tag = payload.subarray(payload.length - 16);
  const encrypted = payload.subarray(12, payload.length - 16);
  const decipher = createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(encrypted), decipher.final()]).toString(
    "utf8",
  );
}

// ---------------------------------------------------------------------------
// Helpers for User model sensitive fields
// ---------------------------------------------------------------------------

/** Encrypt User.lastLocation before writing to Postgres. */
export const encryptLocation = (loc: string | null | undefined) =>
  encryptField(loc);

/** Decrypt User.lastLocation after reading from Postgres. */
export const decryptLocation = (enc: string | null | undefined) =>
  decryptField(enc);
