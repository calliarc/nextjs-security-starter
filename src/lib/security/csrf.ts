/**
 * CSRF protection for Route Handlers.
 *
 * Two independent layers:
 *   1. Origin check - state-changing requests must carry an `Origin` (or, as a
 *      fallback, `Referer`) whose origin matches this app's own origin or an
 *      explicit allow-list. `Sec-Fetch-Site: cross-site` is rejected outright.
 *   2. Signed double-submit token - `GET /api/csrf` sets an HttpOnly cookie
 *      and returns the same token in the body. The client echoes it in the
 *      `x-csrf-token` header. A cross-site attacker can neither read the token
 *      nor forge the HMAC signature.
 *
 * Server Actions do NOT need this: Next.js only allows POST for them and
 * compares Origin with Host / X-Forwarded-Host itself (see
 * `experimental.serverActions.allowedOrigins` in next.config.ts).
 */

export const CSRF_HEADER = "x-csrf-token";
const TOKEN_BYTES = 32;

/** `__Host-` cookies must be Secure, path=/ and host-only, which blocks subdomain overwrites. */
export function csrfCookieName(isProduction = process.env.NODE_ENV === "production"): string {
  return isProduction ? "__Host-csrf" : "csrf";
}

export function csrfCookieOptions(isProduction = process.env.NODE_ENV === "production") {
  return {
    httpOnly: true,
    secure: isProduction,
    sameSite: "strict" as const,
    path: "/",
    maxAge: 60 * 60 * 2,
  };
}

const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS", "TRACE"]);

export function isSafeMethod(method: string): boolean {
  return SAFE_METHODS.has(method.toUpperCase());
}

// ---------------------------------------------------------------------------
// Origin / Host verification
// ---------------------------------------------------------------------------

export interface OriginCheckOptions {
  /** Extra fully-qualified origins allowed to call the API, e.g. `https://admin.example.com`. */
  allowedOrigins?: string[];
  /**
   * Trust `X-Forwarded-Host` / `X-Forwarded-Proto`. Enable only behind a
   * proxy that sets them (most hosting platforms do).
   */
  trustForwardedHeaders?: boolean;
}

export type OriginCheckResult = { ok: true } | { ok: false; reason: string };

function toOrigin(value: string | null): string | null {
  if (!value || value === "null") return null;
  try {
    return new URL(value).origin;
  } catch {
    return null;
  }
}

/** The origin this request was addressed to, derived from Host headers. */
export function expectedOrigin(request: Request, options: OriginCheckOptions = {}): string | null {
  const headers = request.headers;
  const forwardedHost = options.trustForwardedHeaders ? headers.get("x-forwarded-host")?.split(",")[0]?.trim() : undefined;
  const host = forwardedHost || headers.get("host");
  if (!host) return null;

  const forwardedProto = options.trustForwardedHeaders
    ? headers.get("x-forwarded-proto")?.split(",")[0]?.trim()
    : undefined;
  const proto = forwardedProto || new URL(request.url).protocol.replace(":", "");
  return toOrigin(`${proto}://${host}`);
}

export function verifyOrigin(request: Request, options: OriginCheckOptions = {}): OriginCheckResult {
  if (isSafeMethod(request.method)) return { ok: true };

  if (request.headers.get("sec-fetch-site") === "cross-site") {
    return { ok: false, reason: "cross-site request" };
  }

  const source = toOrigin(request.headers.get("origin")) ?? toOrigin(request.headers.get("referer"));
  if (!source) return { ok: false, reason: "missing origin" };

  const allowed = new Set<string>();
  const self = expectedOrigin(request, options);
  if (self) allowed.add(self);
  for (const origin of options.allowedOrigins ?? []) {
    const normalised = toOrigin(origin);
    if (normalised) allowed.add(normalised);
  }

  return allowed.has(source) ? { ok: true } : { ok: false, reason: "origin mismatch" };
}

// ---------------------------------------------------------------------------
// Signed double-submit token
// ---------------------------------------------------------------------------

const encoder = new TextEncoder();

function base64UrlEncode(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function hmac(secret: string, message: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign("HMAC", key, encoder.encode(message));
  return base64UrlEncode(new Uint8Array(signature));
}

/** Constant-time string comparison (length is not secret here). */
export function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

function assertSecret(secret: string | undefined): asserts secret is string {
  if (!secret || secret.length < 32) {
    throw new Error("CSRF secret must be at least 32 characters");
  }
}

/** Resolves the signing secret from the environment. */
export function getCsrfSecret(env: Record<string, string | undefined> = process.env): string {
  const secret = env.CSRF_SECRET || env.AUTH_SECRET;
  assertSecret(secret);
  return secret;
}

/** Creates `<random>.<hmac(random)>`. */
export async function createCsrfToken(secret: string): Promise<string> {
  assertSecret(secret);
  const bytes = new Uint8Array(TOKEN_BYTES);
  crypto.getRandomValues(bytes);
  const value = base64UrlEncode(bytes);
  return `${value}.${await hmac(secret, value)}`;
}

/** Verifies the token's HMAC signature. */
export async function verifyCsrfToken(token: string | null | undefined, secret: string): Promise<boolean> {
  assertSecret(secret);
  if (!token) return false;
  const [value, signature, ...rest] = token.split(".");
  if (!value || !signature || rest.length > 0) return false;
  return timingSafeEqual(signature, await hmac(secret, value));
}

/** Cookie and header must both be present, identical and correctly signed. */
export async function validateDoubleSubmit(
  cookieToken: string | null | undefined,
  headerToken: string | null | undefined,
  secret: string,
): Promise<boolean> {
  if (!cookieToken || !headerToken) return false;
  if (!timingSafeEqual(cookieToken, headerToken)) return false;
  return verifyCsrfToken(headerToken, secret);
}

function readCookie(header: string | null, name: string): string | null {
  if (!header) return null;
  for (const part of header.split(";")) {
    const index = part.indexOf("=");
    if (index === -1) continue;
    if (part.slice(0, index).trim() === name) {
      return decodeURIComponent(part.slice(index + 1).trim());
    }
  }
  return null;
}

export type CsrfCheckResult = { ok: true } | { ok: false; reason: string };

/** Full CSRF check for a Route Handler request (origin + double-submit token). */
export async function verifyCsrf(
  request: Request,
  options: OriginCheckOptions & { secret?: string; cookieName?: string } = {},
): Promise<CsrfCheckResult> {
  if (isSafeMethod(request.method)) return { ok: true };

  const origin = verifyOrigin(request, options);
  if (!origin.ok) return origin;

  const secret = options.secret ?? getCsrfSecret();
  const cookieToken = readCookie(request.headers.get("cookie"), options.cookieName ?? csrfCookieName());
  const headerToken = request.headers.get(CSRF_HEADER);
  const valid = await validateDoubleSubmit(cookieToken, headerToken, secret);
  return valid ? { ok: true } : { ok: false, reason: "invalid csrf token" };
}
