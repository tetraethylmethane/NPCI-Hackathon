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

const SESSION_SECRET =
  process.env.SESSION_SECRET ?? "npci-dev-session-secret-change-me";

const COOKIE_NAME = "npci_session";
const SESSION_TTL_SECONDS = 8 * 60 * 60; // 8 hours

// ---------------------------------------------------------------------------
// Web Crypto HMAC helper (Edge-compatible — no Node.js crypto module)
// ---------------------------------------------------------------------------

async function hmacHex(payload: string, secret: string): Promise<string> {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(payload));
  return Array.from(new Uint8Array(sig))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Encode a session object as a signed cookie value.
 * Format: base64url(JSON) + "." + HMAC-SHA256(base64url(JSON))
 */
export async function encodeSession(session: NpciSession): Promise<string> {
  const payload = btoa(JSON.stringify(session))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
  const sig = await hmacHex(payload, SESSION_SECRET);
  return `${payload}.${sig}`;
}

/**
 * Decode and verify a session cookie value.
 * Returns null if the signature is invalid or the session has expired.
 */
export async function decodeSession(cookie: string): Promise<NpciSession | null> {
  try {
    const dot = cookie.lastIndexOf(".");
    if (dot === -1) return null;
    const payload = cookie.slice(0, dot);
    const sig = cookie.slice(dot + 1);
    const expected = await hmacHex(payload, SESSION_SECRET);
    // Constant-time comparison
    if (sig.length !== expected.length) return null;
    let diff = 0;
    for (let i = 0; i < sig.length; i++) diff |= sig.charCodeAt(i) ^ expected.charCodeAt(i);
    if (diff !== 0) return null;
    const json = atob(payload.replace(/-/g, "+").replace(/_/g, "/"));
    const session: NpciSession = JSON.parse(json);
    if (session.exp < Math.floor(Date.now() / 1000)) return null;
    return session;
  } catch {
    return null;
  }
}

/** Build Set-Cookie header value for the session cookie. */
export async function buildSessionCookie(role: SecurityRole, userId: string): Promise<string> {
  const session: NpciSession = {
    userId,
    role,
    exp: Math.floor(Date.now() / 1000) + SESSION_TTL_SECONDS,
  };
  const value = await encodeSession(session);
  return `${COOKIE_NAME}=${value}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${SESSION_TTL_SECONDS}`;
}

export { COOKIE_NAME };
