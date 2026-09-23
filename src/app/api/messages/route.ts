import { NextResponse } from "next/server";
import { auth } from "@/auth";
import { ApiError } from "@/lib/http/errors";
import { secureRoute } from "@/lib/http/secure-route";
import { parseJsonBody } from "@/lib/validation/body";
import { messageSchema } from "@/lib/validation/schemas";

/**
 * Example protected JSON endpoint:
 *   rate limited (proxy) -> CSRF checked (secureRoute) -> authenticated ->
 *   Zod-validated -> safe errors.
 */
export const POST = secureRoute(async (request) => {
  const session = await auth();
  if (!session?.user) {
    throw new ApiError(401, "unauthorized", "Authentication required.");
  }

  const { message } = await parseJsonBody(request, messageSchema, 4 * 1024);

  // Persist `message` here. Always treat it as untrusted: React escapes it on
  // render, but never pass it to dangerouslySetInnerHTML, SQL or a shell.
  return NextResponse.json({ ok: true, length: message.length, receivedAt: new Date().toISOString() }, { status: 201 });
});
