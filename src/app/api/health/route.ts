export const dynamic = "force-dynamic";

/** Minimal liveness probe; reveals no version or environment details. */
export function GET() {
  return Response.json({ status: "ok" }, { headers: { "Cache-Control": "no-store" } });
}
