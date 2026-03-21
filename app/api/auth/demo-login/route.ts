/**
 * GET /api/auth/demo-login?role=ADMIN|ANALYST|VIEWER&redirect=/
 * =============================================================
 * Sprint 5 — Demo session bootstrapper
 *
 * Issues a signed NPCI session cookie for the requested role so evaluators
 * can test the full RBAC matrix without a real identity provider.
 *
 * In production this endpoint MUST be removed or gated behind real auth.
 * Protected by DEMO_MODE env var — returns 404 if not set to "true".
 */

import { NextRequest, NextResponse } from "next/server";
import { buildSessionCookie, type SecurityRole } from "@/lib/auth/rbac";

const VALID_ROLES: SecurityRole[] = ["ADMIN", "ANALYST", "VIEWER"];

export async function GET(request: NextRequest) {
  // Only available in demo / evaluation mode
  if (process.env.DEMO_MODE !== "true") {
    return NextResponse.json({ error: "Not found" }, { status: 404 });
  }

  const { searchParams } = request.nextUrl;
  const role = (searchParams.get("role") ?? "VIEWER").toUpperCase() as SecurityRole;
  const redirect = searchParams.get("redirect") ?? "/";

  if (!VALID_ROLES.includes(role)) {
    return NextResponse.json(
      { error: `Invalid role. Use one of: ${VALID_ROLES.join(", ")}` },
      { status: 400 },
    );
  }

  // Use a fixed demo user ID so audit logs are traceable
  const demoUserId = `demo-${role.toLowerCase()}`;
  const cookie = buildSessionCookie(role, demoUserId);

  const response = NextResponse.redirect(new URL(redirect, request.url));
  response.headers.set("Set-Cookie", cookie);
  return response;
}

/**
 * DELETE /api/auth/demo-login — clear the session cookie (logout)
 */
export async function DELETE() {
  const response = NextResponse.json({ ok: true });
  response.headers.set(
    "Set-Cookie",
    "npci_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0",
  );
  return response;
}
