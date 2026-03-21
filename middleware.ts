/**
 * middleware.ts
 * =============
 * Sprint 5 — Route-Level RBAC Enforcement
 *
 * Runs at the Edge before every matched request.
 *
 * Role → access matrix:
 *   ADMIN   — full dashboard + all API routes
 *   ANALYST — dashboard + /api/alerts + /api/users (drilldown)
 *   VIEWER  — dashboard + /api/alerts + /api/risk-summary (read-only)
 *
 * Session is carried in a signed HttpOnly cookie "npci_session".
 * Unauthenticated requests to protected routes get a 401 JSON response.
 *
 * Public routes (no auth required):
 *   /api/auth/**         — demo login / logout
 *   /api/health          — liveness check
 *   /_next/**            — Next.js internals
 *   /favicon.ico
 */

import { NextRequest, NextResponse } from "next/server";
import {
  decodeSession,
  can,
  ROUTE_PERMISSIONS,
  COOKIE_NAME,
  type SecurityRole,
} from "@/lib/auth/rbac";

// ---------------------------------------------------------------------------
// Route matcher configuration
// ---------------------------------------------------------------------------

export const config = {
  matcher: [
    /*
     * Match all paths except:
     *  - _next/static  (static files)
     *  - _next/image   (image optimisation)
     *  - favicon.ico
     *  - /api/auth/**  (login / logout — always public)
     */
    "/((?!_next/static|_next/image|favicon.ico|api/auth).*)",
  ],
};

// ---------------------------------------------------------------------------
// Middleware handler
// ---------------------------------------------------------------------------

export function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl;

  // ── Determine required permission for this route ──────────────────────────
  const routeRule = ROUTE_PERMISSIONS.find((r) =>
    pathname.startsWith(r.prefix),
  );

  // No rule → public route (static pages, etc.) — pass through
  if (!routeRule) return NextResponse.next();

  // ── Extract and verify session cookie ─────────────────────────────────────
  const cookieValue = request.cookies.get(COOKIE_NAME)?.value ?? null;
  const session = cookieValue ? decodeSession(cookieValue) : null;

  if (!session) {
    return apiOrRedirect(request, 401, "Authentication required. Please log in.");
  }

  // ── Check permission ───────────────────────────────────────────────────────
  if (!can(session.role as SecurityRole, routeRule.permission)) {
    return apiOrRedirect(
      request,
      403,
      `Access denied. This action requires a higher privilege level (current: ${session.role}).`,
    );
  }

  // ── Attach role to request headers for downstream use ─────────────────────
  const response = NextResponse.next();
  response.headers.set("x-npci-role", session.role);
  response.headers.set("x-npci-user-id", session.userId);
  return response;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Return a JSON 401/403 for API routes, redirect to /login for page routes.
 */
function apiOrRedirect(
  request: NextRequest,
  status: 401 | 403,
  message: string,
): NextResponse {
  const isApiRoute = request.nextUrl.pathname.startsWith("/api/");
  if (isApiRoute) {
    return NextResponse.json({ error: message }, { status });
  }
  const loginUrl = new URL("/api/auth/demo-login", request.url);
  loginUrl.searchParams.set("redirect", request.nextUrl.pathname);
  return NextResponse.redirect(loginUrl);
}
