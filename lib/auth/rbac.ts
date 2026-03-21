/**
 * lib/auth/rbac.ts
 * =================
 * Sprint 5 — Role-Based Access Control
 *
 * Defines the three NPCI dashboard roles and the permissions each grants.
 * Used by middleware.ts (route guard) and individual API route handlers.
 *
 * Role hierarchy (most → least privileged):
 *   ADMIN   — full dashboard + Kill Switch + audit log
 *   ANALYST — alerts + user drilldown; cannot lock accounts or view audit log
 *   VIEWER  — summary stats and alert list (read-only, no drilldown)
 */

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type SecurityRole = "ADMIN" | "ANALYST" | "VIEWER";

export interface NpciSession {
  userId: string;
  role: SecurityRole;
  exp: number; // unix timestamp seconds
}

// ---------------------------------------------------------------------------
// Permission constants
// ---------------------------------------------------------------------------

/** Actions that each role is permitted to perform. */
export const PERMISSIONS: Record<SecurityRole, Set<string>> = {
  ADMIN: new Set([
    "view:dashboard",
    "view:alerts",
    "view:drilldown",
    "view:audit_log",
    "action:lock_account",
    "action:unlock_account",
    "action:dismiss_alert",
    "action:trigger_audit",
  ]),
  ANALYST: new Set([
    "view:dashboard",
    "view:alerts",
    "view:drilldown",
    "action:dismiss_alert",
  ]),
  VIEWER: new Set([
    "view:dashboard",
    "view:alerts",
  ]),
};

/** Returns true if the given role has the requested permission. */
export function can(role: SecurityRole, permission: string): boolean {
  return PERMISSIONS[role]?.has(permission) ?? false;
}

// ---------------------------------------------------------------------------
// Route → required permission mapping
// ---------------------------------------------------------------------------

/** Minimum permission required to access each protected route prefix. */
export const ROUTE_PERMISSIONS: Array<{ prefix: string; permission: string }> = [
  { prefix: "/api/admin",                   permission: "action:trigger_audit" },
  { prefix: "/api/users",                   permission: "view:drilldown" },
  { prefix: "/api/alerts",                  permission: "view:alerts" },
  { prefix: "/api/risk-summary",            permission: "view:dashboard" },
];

// ---------------------------------------------------------------------------
// Session cookie helpers
// ---------------------------------------------------------------------------

import { createHmac } from "crypto";

const SESSION_SECRET =
  process.env.SESSION_SECRET ?? "npci-dev-session-secret-change-me";

const COOKIE_NAME = "npci_session";
const SESSION_TTL_SECONDS = 8 * 60 * 60; // 8 hours

/**
 * Encode a session object as a signed cookie value.
 * Format: base64url(JSON) + "." + HMAC-SHA256(base64url(JSON))
 */
export function encodeSession(session: NpciSession): string {
  const payload = Buffer.from(JSON.stringify(session)).toString("base64url");
  const sig = createHmac("sha256", SESSION_SECRET).update(payload).digest("hex");
  return `${payload}.${sig}`;
}

/**
 * Decode and verify a session cookie value.
 * Returns null if the signature is invalid or the session has expired.
 */
export function decodeSession(cookie: string): NpciSession | null {
  try {
    const dot = cookie.lastIndexOf(".");
    if (dot === -1) return null;
    const payload = cookie.slice(0, dot);
    const sig = cookie.slice(dot + 1);
    const expected = createHmac("sha256", SESSION_SECRET)
      .update(payload)
      .digest("hex");
    // Constant-time comparison
    if (sig.length !== expected.length) return null;
    let diff = 0;
    for (let i = 0; i < sig.length; i++) diff |= sig.charCodeAt(i) ^ expected.charCodeAt(i);
    if (diff !== 0) return null;
    const session: NpciSession = JSON.parse(
      Buffer.from(payload, "base64url").toString("utf8"),
    );
    if (session.exp < Math.floor(Date.now() / 1000)) return null;
    return session;
  } catch {
    return null;
  }
}

/** Build Set-Cookie header value for the session cookie. */
export function buildSessionCookie(role: SecurityRole, userId: string): string {
  const session: NpciSession = {
    userId,
    role,
    exp: Math.floor(Date.now() / 1000) + SESSION_TTL_SECONDS,
  };
  const value = encodeSession(session);
  return `${COOKIE_NAME}=${value}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${SESSION_TTL_SECONDS}`;
}

export { COOKIE_NAME };
