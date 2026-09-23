# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-09-23

First working release.

### Added

- Strict Content-Security-Policy with a fresh nonce per request (`'strict-dynamic'`, no `'unsafe-inline'`)
- Security headers configured in one place (HSTS, nosniff, Referrer-Policy, Permissions-Policy, COOP/CORP, frame-ancestors)
- Authentication with secure session cookies (Auth.js v5, credentials provider plus optional GitHub OAuth, protected `/dashboard`)
- CSRF protection for server actions and API routes (Origin check plus a signed double-submit token for Route Handlers)
- Rate limiting for login and API endpoints (token bucket with a pluggable store)
- Input validation with Zod and safe error handling (no stack traces reach clients)
- `/.well-known/security.txt` (RFC 9116)
- Dependency and secret scanning in CI (`npm audit`, gitleaks, Dependabot)

[Unreleased]: https://github.com/calliarc/nextjs-security-starter/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/calliarc/nextjs-security-starter/releases/tag/v0.1.0
