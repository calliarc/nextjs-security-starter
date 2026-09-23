import Link from "next/link";

const features = [
  ["Strict CSP with nonces", "A fresh nonce per request, 'strict-dynamic', no 'unsafe-inline'. Inspect the response headers."],
  ["Security headers in one place", "HSTS, nosniff, Referrer-Policy, Permissions-Policy, COOP/CORP and frame-ancestors from src/lib/security/headers.ts."],
  ["Auth.js sessions", "HttpOnly, SameSite=Lax, __Secure- prefixed JWT session cookies with an 8 hour lifetime."],
  ["CSRF protection", "Origin checks plus a signed double-submit token for Route Handlers; Server Actions use Next.js' built-in origin check."],
  ["Rate limiting", "Token buckets on login and /api/* with a pluggable store (swap in Redis/Upstash for production)."],
  ["Validation and safe errors", "Zod schemas, body size limits and generic error responses without stack traces."],
] as const;

export default function HomePage() {
  return (
    <>
      <h1>Next.js Security Starter</h1>
      <p>
        A Next.js App Router template with secure defaults. Sign in with the demo account configured in{" "}
        <code>.env.local</code> and open the <Link href="/dashboard">dashboard</Link> to try the protected
        endpoints.
      </p>
      {features.map(([title, body]) => (
        <section key={title} className="card">
          <h2>{title}</h2>
          <p className="muted">{body}</p>
        </section>
      ))}
      <p>
        Vulnerability disclosure: <a href="/.well-known/security.txt">/.well-known/security.txt</a>
      </p>
    </>
  );
}
