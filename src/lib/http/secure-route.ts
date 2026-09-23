import type { NextRequest } from "next/server";
import { verifyCsrf, type OriginCheckOptions } from "@/lib/security/csrf";
import { handleRouteError, jsonError } from "@/lib/http/errors";

type Handler<C> = (request: NextRequest, context: C) => Promise<Response> | Response;

export interface SecureRouteOptions extends OriginCheckOptions {
  /** Enforce Origin + double-submit CSRF token on unsafe methods. Default: true. */
  csrf?: boolean;
}

/**
 * Wraps a Route Handler with CSRF checks and safe error handling.
 * Rate limiting for `/api/*` happens earlier, in `src/proxy.ts`.
 */
export function secureRoute<C = unknown>(handler: Handler<C>, options: SecureRouteOptions = {}): Handler<C> {
  const { csrf = true, ...originOptions } = options;
  return async (request, context) => {
    try {
      if (csrf) {
        const result = await verifyCsrf(request, {
          trustForwardedHeaders: process.env.TRUST_PROXY_HEADERS === "true",
          ...originOptions,
        });
        if (!result.ok) {
          // Do not reveal which check failed.
          return jsonError(403, "forbidden", "Request blocked.");
        }
      }
      const response = await handler(request, context);
      if (!response.headers.has("Cache-Control")) response.headers.set("Cache-Control", "no-store");
      return response;
    } catch (error) {
      return handleRouteError(error);
    }
  };
}
