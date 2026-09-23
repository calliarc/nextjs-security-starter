import { NextResponse, type NextRequest } from "next/server";
import { API_CSP, buildCsp, generateNonce } from "@/lib/security/csp";
import { applySecurityHeaders } from "@/lib/security/headers";
import { apiLimiter, loginLimiter, rateLimitHeaders } from "@/lib/security/rate-limit";
import { getClientIp } from "@/lib/security/client-ip";

/**
 * Next.js 16 "proxy" (formerly middleware). Runs on the Node.js runtime for
 * every matched request and:
 *   1. rate-limits login attempts and API calls per client IP,
 *   2. redirects anonymous users away from /dashboard (optimistic check; the
 *      page itself verifies the session again),
 *   3. generates a per-request nonce and sets a strict CSP + security headers.
 */

const isDev = process.env.NODE_ENV === "development";

// GitHub OAuth sign-in submits a form that redirects to github.com; CSP
// `form-action` also applies to that redirect.
const extraFormAction = process.env.AUTH_GITHUB_ID ? ["https://github.com"] : [];

const PROTECTED_PREFIXES = ["/dashboard"];

function isLoginAttempt(request: NextRequest): boolean {
  if (request.method !== "POST") return false;
  const { pathname } = request.nextUrl;
  return pathname === "/login" || pathname.startsWith("/api/auth/callback") || pathname.startsWith("/api/auth/signin");
}

function hasSessionCookie(request: NextRequest): boolean {
  // Auth.js uses `authjs.session-token` (or `__Secure-` prefixed; may be chunked `.0`, `.1`).
  return request.cookies.getAll().some(({ name }) => name.includes("authjs.session-token"));
}

function tooManyRequests(headers: Record<string, string>, isApi: boolean): NextResponse {
  const response = NextResponse.json(
    { error: { code: "rate_limited", message: "Too many requests. Please try again later." } },
    { status: 429, headers: { ...headers, "Cache-Control": "no-store" } },
  );
  applySecurityHeaders(response.headers, isApi ? API_CSP : undefined);
  return response;
}

export async function proxy(request: NextRequest) {
  const { pathname } = request.nextUrl;
  const isApi = pathname.startsWith("/api/");
  const ip = getClientIp(request.headers);

  // 1. Rate limiting ---------------------------------------------------------
  let limitHeaders: Record<string, string> | undefined;
  if (isLoginAttempt(request)) {
    const result = await loginLimiter.limit(`ip:${ip}`);
    if (!result.allowed) return tooManyRequests(rateLimitHeaders(result), isApi);
    limitHeaders = rateLimitHeaders(result);
  } else if (isApi) {
    const result = await apiLimiter.limit(`ip:${ip}`);
    if (!result.allowed) return tooManyRequests(rateLimitHeaders(result), true);
    limitHeaders = rateLimitHeaders(result);
  }

  // 2. Optimistic auth redirect --------------------------------------------
  if (PROTECTED_PREFIXES.some((prefix) => pathname === prefix || pathname.startsWith(`${prefix}/`))) {
    if (!hasSessionCookie(request)) {
      const loginUrl = new URL("/login", request.url);
      loginUrl.searchParams.set("callbackUrl", pathname);
      const response = NextResponse.redirect(loginUrl);
      applySecurityHeaders(response.headers);
      return response;
    }
  }

  // 3. CSP with per-request nonce -------------------------------------------
  const nonce = generateNonce();
  const csp = isApi ? API_CSP : buildCsp({ nonce, isDev, extend: { "form-action": extraFormAction } });

  const requestHeaders = new Headers(request.headers);
  // Next.js reads the nonce from the request CSP header while rendering.
  requestHeaders.set("x-nonce", nonce);
  requestHeaders.set("Content-Security-Policy", csp);

  const response = NextResponse.next({ request: { headers: requestHeaders } });
  applySecurityHeaders(response.headers, csp);
  if (limitHeaders) {
    for (const [key, value] of Object.entries(limitHeaders)) response.headers.set(key, value);
  }
  return response;
}

export const config = {
  matcher: [
    {
      // Everything except static build assets and the favicon.
      source: "/((?!_next/static|_next/image|favicon.ico).*)",
      missing: [
        { type: "header", key: "next-router-prefetch" },
        { type: "header", key: "purpose", value: "prefetch" },
      ],
    },
  ],
};
