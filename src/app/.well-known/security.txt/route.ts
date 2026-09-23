/**
 * RFC 9116 security.txt served at /.well-known/security.txt.
 * Configure via SECURITY_CONTACT (mailto: or https: URL), SECURITY_POLICY_URL
 * and APP_URL.
 */
export const dynamic = "force-dynamic";

const DEFAULT_CONTACT = "https://github.com/calliarc/nextjs-security-starter/security/advisories/new";
const DEFAULT_POLICY = "https://github.com/calliarc/nextjs-security-starter/blob/main/SECURITY.md";
const VALIDITY_DAYS = 180;

export function GET() {
  // Canonical is only emitted when APP_URL is configured; it is never derived
  // from the (client-controlled) Host header.
  const appUrl = process.env.APP_URL?.replace(/\/+$/, "");
  const expires = new Date(Date.now() + VALIDITY_DAYS * 24 * 60 * 60 * 1000);
  expires.setUTCHours(0, 0, 0, 0);

  const body = [
    `Contact: ${process.env.SECURITY_CONTACT || DEFAULT_CONTACT}`,
    `Expires: ${expires.toISOString()}`,
    `Policy: ${process.env.SECURITY_POLICY_URL || DEFAULT_POLICY}`,
    "Preferred-Languages: en",
    ...(appUrl ? [`Canonical: ${appUrl}/.well-known/security.txt`] : []),
    "",
  ].join("\n");

  return new Response(body, {
    headers: {
      "Content-Type": "text/plain; charset=utf-8",
      "Cache-Control": "public, max-age=86400",
    },
  });
}
