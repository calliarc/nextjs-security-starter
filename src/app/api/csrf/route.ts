import { NextResponse } from "next/server";
import { createCsrfToken, csrfCookieName, csrfCookieOptions, getCsrfSecret } from "@/lib/security/csrf";
import { handleRouteError } from "@/lib/http/errors";

export const dynamic = "force-dynamic";

/**
 * Issues a signed CSRF token: set as an HttpOnly, SameSite=Strict cookie and
 * returned in the body so same-origin JavaScript can echo it in the
 * `x-csrf-token` header. Cross-origin pages cannot read this response.
 */
export async function GET() {
  try {
    const token = await createCsrfToken(getCsrfSecret());
    const response = NextResponse.json({ token }, { headers: { "Cache-Control": "no-store" } });
    response.cookies.set(csrfCookieName(), token, csrfCookieOptions());
    return response;
  } catch (error) {
    return handleRouteError(error);
  }
}
