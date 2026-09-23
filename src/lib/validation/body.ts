import type { z } from "zod";
import { ApiError } from "@/lib/http/errors";

export const DEFAULT_MAX_BODY_BYTES = 16 * 1024;

/**
 * Reads a JSON body with a content-type check and a hard size limit, then
 * validates it with Zod. Throws `ApiError` / `ZodError`, which
 * `handleRouteError` turns into safe responses.
 */
export async function parseJsonBody<T extends z.ZodType>(
  request: Request,
  schema: T,
  maxBytes = DEFAULT_MAX_BODY_BYTES,
): Promise<z.infer<T>> {
  const contentType = request.headers.get("content-type") ?? "";
  if (!contentType.toLowerCase().startsWith("application/json")) {
    throw new ApiError(415, "unsupported_media_type", "Content-Type must be application/json.");
  }

  const declared = Number(request.headers.get("content-length") ?? "0");
  if (declared > maxBytes) {
    throw new ApiError(413, "payload_too_large", "Request body is too large.");
  }

  const text = await request.text();
  if (new TextEncoder().encode(text).byteLength > maxBytes) {
    throw new ApiError(413, "payload_too_large", "Request body is too large.");
  }

  let data: unknown;
  try {
    data = JSON.parse(text);
  } catch {
    throw new ApiError(400, "invalid_json", "Request body is not valid JSON.");
  }

  return schema.parse(data);
}
