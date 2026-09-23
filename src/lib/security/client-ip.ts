/**
 * Best-effort client IP extraction for rate-limit keys.
 *
 * `X-Forwarded-For` / `X-Real-IP` are only trustworthy when your app sits
 * behind a proxy that overwrites them (Vercel, Cloudflare, a correctly
 * configured nginx/ALB). If clients can reach the Node server directly they can
 * spoof these headers, so configure your edge accordingly.
 */
export function getClientIp(headers: Headers): string {
  const realIp = headers.get("x-real-ip")?.trim();
  if (realIp) return realIp;

  const forwarded = headers.get("x-forwarded-for");
  if (forwarded) {
    const first = forwarded.split(",")[0]?.trim();
    if (first) return first;
  }

  return "unknown";
}
