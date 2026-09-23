# Next.js Security Starter

Next.js template with secure headers, rate limiting, CSRF protection and auth set up correctly.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![Status: v0.1.0](https://img.shields.io/badge/status-v0.1.0-green)
[![CI](https://github.com/calliarc/nextjs-security-starter/actions/workflows/ci.yml/badge.svg)](https://github.com/calliarc/nextjs-security-starter/actions/workflows/ci.yml)

> **Status:** working v0.1.0. The template builds, the tests pass, and every feature below is in place. Feedback and issues are welcome.

## Features

- Strict Content-Security-Policy with a fresh nonce per request (`'strict-dynamic'`, no `'unsafe-inline'`)
- Security headers configured in one place (HSTS, nosniff, Referrer-Policy, Permissions-Policy, COOP/CORP, frame-ancestors)
- Authentication with secure session cookies (Auth.js v5, credentials provider plus optional GitHub OAuth, protected `/dashboard`)
- CSRF protection for server actions and API routes (Origin check plus a signed double-submit token for Route Handlers)
- Rate limiting for login and API endpoints (token bucket with a pluggable store)
- Input validation with Zod and safe error handling (no stack traces reach clients)
- `/.well-known/security.txt` (RFC 9116)
- Dependency and secret scanning in CI (`npm audit`, gitleaks, Dependabot)

## Tech stack

- Next.js 16 (App Router, `proxy.ts`)
- TypeScript (strict)
- Auth.js (`next-auth` v5)
- Zod 4
- Proxy-based (formerly "middleware") rate limiting
- Vitest, ESLint, GitHub Actions

## Getting started

Requirements: Node.js 20.9 or later (CI uses Node 22) and npm.

```bash
git clone https://github.com/calliarc/nextjs-security-starter.git
cd nextjs-security-starter
npm ci
cp .env.example .env.local
```

Fill in `.env.local`:

```bash
# 1. Session signing secret
npx auth secret            # or: openssl rand -base64 32  -> AUTH_SECRET=

# 2. Demo user password hash (the prompt hides your input)
npm run hash-password      # paste the output into DEMO_USER_PASSWORD_HASH=
```

Then run the app:

```bash
npm run dev                # http://localhost:3000
```

Sign in at `/login` with `DEMO_USER_EMAIL` and the password you hashed. The dashboard shows a Server Action form and a Route Handler form that uses a CSRF token.

To enable GitHub sign-in, create an OAuth app with the callback `http://localhost:3000/api/auth/callback/github` and set `AUTH_GITHUB_ID` / `AUTH_GITHUB_SECRET`.

### Scripts

| Command | What it does |
| --- | --- |
| `npm run dev` | Development server |
| `npm run build` / `npm start` | Production build and server |
| `npm run lint` | ESLint (`eslint-config-next` core-web-vitals + TypeScript) |
| `npm run typecheck` | `tsc --noEmit` |
| `npm test` | Vitest unit tests for the CSP, rate-limit, CSRF and validation helpers |
| `npm run hash-password` | Prints an scrypt hash for `DEMO_USER_PASSWORD_HASH` |

### Project layout

```
src/
  proxy.ts                      # nonce + CSP, security headers, rate limiting, optimistic auth redirect
  auth.ts                       # Auth.js config (providers, cookies, session, redirect guard)
  lib/security/
    csp.ts                      # nonce generation and CSP builder
    headers.ts                  # every other security header, in one place
    csrf.ts                     # Origin check and signed double-submit tokens
    rate-limit.ts               # token bucket, RateLimitStore interface, MemoryStore
    password.ts                 # scrypt hashing
    client-ip.ts                # client IP used as the rate-limit key
  lib/http/                     # safe error responses, secureRoute() wrapper
  lib/validation/               # Zod schemas and a size-limited JSON body parser
  app/
    .well-known/security.txt/   # RFC 9116 security.txt
    api/csrf, api/messages      # CSRF token endpoint and an example protected endpoint
    login, dashboard            # sign-in page and protected page with Server Actions
tests/                          # Vitest unit tests
```

## Security features explained

### Content-Security-Policy with nonces

`src/proxy.ts` creates a 128-bit random nonce for every request. It sets the CSP on the response, and on the request as well, which is how Next.js finds the nonce and adds it to its own scripts and styles. The policy looks like this:

```
default-src 'self'; script-src 'self' 'nonce-…' 'strict-dynamic'; style-src 'self' 'nonce-…';
object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; upgrade-insecure-requests; …
```

- `'unsafe-eval'` is added **only** in development, because React's dev tooling needs it.
- Nonces only work with dynamic rendering, so the root layout calls `connection()`. This means no page is statically prerendered.
- To allow extra origins, use `cspDirectives({ extend: { "img-src": ["https://…"] } })`. The GitHub provider adds `https://github.com` to `form-action` automatically.
- API responses get `default-src 'none'; frame-ancestors 'none'`.

### Security headers in one place

All other headers are defined in `src/lib/security/headers.ts`. `next.config.ts` applies them to every path, and the proxy also applies them to the redirects and 429 responses it creates itself:

| Header | Value |
| --- | --- |
| `Strict-Transport-Security` | `max-age=63072000; includeSubDomains` (production only; `preload` is opt-in) |
| `X-Content-Type-Options` | `nosniff` |
| `Referrer-Policy` | `strict-origin-when-cross-origin` |
| `Permissions-Policy` | camera, microphone, geolocation, payment, usb, topics and others disabled |
| `X-Frame-Options` / CSP `frame-ancestors` | `DENY` / `'none'` |
| `Cross-Origin-Opener-Policy` / `-Resource-Policy` | `same-origin` |
| `X-Powered-By` | removed (`poweredByHeader: false`) |

### Authentication and session cookies

`src/auth.ts` configures Auth.js v5:

- JWT sessions last 8 hours and are re-issued at most once an hour.
- In production the cookies use the `__Secure-` prefix and are `Secure`, `HttpOnly` and `SameSite=Lax`.
- The credentials provider validates input with Zod and hashes passwords with scrypt. It runs the hash even for unknown emails, so response time does not reveal whether an account exists, and it returns the same error for a wrong email or a wrong password.
- The login is rate limited per account.
- The `redirect` callback and the login action only accept same-site callback URLs, which blocks open redirects.
- `/dashboard` is protected twice. The proxy does a quick cookie-presence redirect, and the page itself calls `auth()`. Server Actions and Route Handlers also call `auth()` themselves, because a proxy matcher is not a security boundary.

The demo user is read from env vars. Replace `findUser()` with a database lookup, and consider argon2id or bcrypt through your user store.

### CSRF protection

- **Server Actions:** Next.js only accepts `POST` for them and rejects any call whose `Origin` host differs from `Host` / `X-Forwarded-Host`. You don't need a token. If a reverse proxy rewrites the host, list the public host in `experimental.serverActions.allowedOrigins`. Note that a request with **no** `Origin` header is allowed through with a warning, so SameSite cookies are still your second layer.
- **Route Handlers:** wrap them in `secureRoute()` (`src/lib/http/secure-route.ts`). For unsafe methods it runs two checks:
  1. **Origin check.** `Origin` (falling back to `Referer`) must match the app's own origin or an allow-list. `Sec-Fetch-Site: cross-site` is always rejected. `X-Forwarded-*` headers are ignored unless `TRUST_PROXY_HEADERS=true`.
  2. **Signed double-submit token.** `GET /api/csrf` returns `<random>.<HMAC>`. It also sets the token in an `HttpOnly`, `SameSite=Strict` cookie, which is named `__Host-csrf` in production. The client sends the token back in `x-csrf-token`. The cookie and header must match, and the HMAC must verify against `CSRF_SECRET` (or `AUTH_SECRET` if `CSRF_SECRET` is not set).

  If either check fails, the response is a generic `403`.

### Rate limiting

`src/lib/security/rate-limit.ts` implements a token bucket. Each key has a bucket of `capacity` tokens that refills at `refillPerSecond`. `src/proxy.ts` applies the limits per client IP:

- **Login** (`POST /login`, `/api/auth/callback/*`, `/api/auth/signin/*`): a burst of 5, then 5 per minute. `authorize()` applies the same limit per email address.
- **API** (`/api/*`): a burst of 30, then 1 request per second.

Responses include `RateLimit-Limit` and `RateLimit-Remaining`. Blocked requests get a `429` with `Retry-After`.

**Rate limiting in production:** the default `MemoryStore` works per process. It resets on deploy and is not shared across instances or serverless invocations. For multi-instance deployments, implement the `RateLimitStore` interface on top of Redis. Use a Lua script (or Upstash's `@upstash/ratelimit`) so that consume stays atomic, then pass that store to the `RateLimiter` instances.

Client IPs come from `X-Real-IP` / `X-Forwarded-For`. These headers can only be trusted behind a proxy that overwrites them, such as Vercel, Cloudflare, or a correctly configured nginx or load balancer.

### Input validation and safe errors

- Zod schemas live in `src/lib/validation/schemas.ts`. `parseJsonBody()` enforces `Content-Type: application/json`, a byte limit and valid JSON before it validates.
- `handleRouteError()` handles three cases:
  - Zod errors: returns `400` with a list of field paths and messages.
  - `ApiError`: returns its own status and a public message.
  - Anything else: logs the full error server-side under a request id and returns `{ "error": { "code": "internal_error", "message": "Something went wrong.", "requestId": "…" } }`. Stack traces are never sent to clients.
- `error.tsx` / `global-error.tsx` show only the opaque `digest`. Server Action bodies are capped at 100 KB.

### security.txt

`/.well-known/security.txt` is served by a route handler. Its `Expires` field is always 180 days ahead. Set `SECURITY_CONTACT`, `SECURITY_POLICY_URL` and `APP_URL` to point it at your own disclosure process.

### CI and supply chain

`.github/workflows/ci.yml` runs these jobs on every push and pull request:

- lint, typecheck, test and build
- `npm audit --audit-level=high`
- a full-history gitleaks secret scan

Workflow permissions are read-only and checkout credentials are not persisted. Dependabot (`.github/dependabot.yml`) opens weekly updates for npm packages and GitHub Actions.

## Roadmap

- [x] Initial release
- [x] Documentation and examples
- [x] CI and automated tests
- [ ] Redis / Upstash `RateLimitStore` adapter
- [ ] CSP violation reporting endpoint (`report-to`)
- [ ] End-to-end tests (Playwright) for auth and CSRF flows

Have an idea? [Open an issue](https://github.com/calliarc/nextjs-security-starter/issues).

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[MIT](LICENSE) © 2026 CalliArc

---

Built and maintained by [CalliArc](https://www.calliarc.com/). Need help with secure application development? [Talk to our team](https://www.calliarc.com/services/managed-cyber-security/).
