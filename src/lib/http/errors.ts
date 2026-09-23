import { ZodError } from "zod";

/**
 * Safe error responses: clients get a stable code and a generic message.
 * Stack traces, SQL errors, file paths etc. are only ever logged server-side,
 * correlated by a request id.
 */

export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    /** Message that is safe to show to the client. */
    readonly publicMessage: string,
    readonly headers: Record<string, string> = {},
  ) {
    super(publicMessage);
    this.name = "ApiError";
  }
}

export interface ErrorBody {
  error: {
    code: string;
    message: string;
    requestId?: string;
    issues?: { path: string; message: string }[];
  };
}

const NO_STORE = { "Cache-Control": "no-store" };

export function jsonError(
  status: number,
  code: string,
  message: string,
  extra: Partial<ErrorBody["error"]> = {},
  headers: Record<string, string> = {},
): Response {
  const body: ErrorBody = { error: { code, message, ...extra } };
  return Response.json(body, { status, headers: { ...NO_STORE, ...headers } });
}

/** Converts Zod issues into a client-safe list (field path + message only). */
export function formatZodIssues(error: ZodError): { path: string; message: string }[] {
  return error.issues.map((issue) => ({
    path: issue.path.map(String).join(".") || "(root)",
    message: issue.message,
  }));
}

/** Maps any thrown value to a safe HTTP response. */
export function handleRouteError(error: unknown): Response {
  if (error instanceof ApiError) {
    return jsonError(error.status, error.code, error.publicMessage, {}, error.headers);
  }
  if (error instanceof ZodError) {
    return jsonError(400, "invalid_request", "The request body is invalid.", { issues: formatZodIssues(error) });
  }

  const requestId = crypto.randomUUID();
  // Full detail goes to server logs only.
  console.error(`[${requestId}] Unhandled route error`, error);
  return jsonError(500, "internal_error", "Something went wrong.", { requestId });
}
