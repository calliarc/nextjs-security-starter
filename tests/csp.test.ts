import { describe, expect, it } from "vitest";
import { API_CSP, buildCsp, cspDirectives, generateNonce, serializeCsp } from "@/lib/security/csp";
import { permissionsPolicyValue, staticSecurityHeaders } from "@/lib/security/headers";

describe("generateNonce", () => {
  it("returns 128-bit base64 values", () => {
    const nonce = generateNonce();
    expect(nonce).toMatch(/^[A-Za-z0-9+/]{22}==$/);
    expect(atob(nonce)).toHaveLength(16);
  });

  it("is unique per call", () => {
    const nonces = new Set(Array.from({ length: 1000 }, generateNonce));
    expect(nonces.size).toBe(1000);
  });
});

describe("buildCsp", () => {
  const nonce = "dGVzdC1ub25jZS0xMjM0NQ==";

  it("builds a strict production policy", () => {
    const csp = buildCsp({ nonce });
    expect(csp).toContain(`script-src 'self' 'nonce-${nonce}' 'strict-dynamic'`);
    expect(csp).toContain(`style-src 'self' 'nonce-${nonce}'`);
    expect(csp).toContain("object-src 'none'");
    expect(csp).toContain("base-uri 'self'");
    expect(csp).toContain("frame-ancestors 'none'");
    expect(csp).toContain("form-action 'self'");
    expect(csp).toContain("upgrade-insecure-requests");
    expect(csp).not.toContain("unsafe-inline");
    expect(csp).not.toContain("unsafe-eval");
  });

  it("only allows unsafe-eval in development", () => {
    const csp = buildCsp({ nonce, isDev: true });
    expect(csp).toContain("'unsafe-eval'");
    expect(csp).not.toContain("upgrade-insecure-requests");
  });

  it("merges extra sources without duplicates and replaces 'none'", () => {
    const d = cspDirectives({
      nonce,
      extend: { "form-action": ["https://github.com", "'self'"], "frame-src": ["https://www.youtube-nocookie.com"] },
    });
    expect(d["form-action"]).toEqual(["'self'", "https://github.com"]);
    expect(d["frame-src"]).toEqual(["https://www.youtube-nocookie.com"]);
  });

  it("rejects malformed nonces (header injection)", () => {
    expect(() => buildCsp({ nonce: "abc'; script-src *" })).toThrow();
    expect(() => buildCsp({ nonce: "" })).toThrow();
  });

  it("serialises valueless directives and report-uri", () => {
    expect(serializeCsp({ "default-src": ["'self'"], "upgrade-insecure-requests": [] }, "/csp-report")).toBe(
      "default-src 'self'; upgrade-insecure-requests; report-uri /csp-report",
    );
  });

  it("locks API responses down completely", () => {
    expect(API_CSP).toContain("default-src 'none'");
    expect(API_CSP).toContain("frame-ancestors 'none'");
  });
});

describe("staticSecurityHeaders", () => {
  const toMap = (hsts: boolean) => new Map(staticSecurityHeaders({ hsts }).map((h) => [h.key, h.value]));

  it("sets the baseline headers", () => {
    const headers = toMap(true);
    expect(headers.get("X-Content-Type-Options")).toBe("nosniff");
    expect(headers.get("Referrer-Policy")).toBe("strict-origin-when-cross-origin");
    expect(headers.get("Cross-Origin-Opener-Policy")).toBe("same-origin");
    expect(headers.get("X-Frame-Options")).toBe("DENY");
    expect(headers.get("Strict-Transport-Security")).toBe("max-age=63072000; includeSubDomains");
    expect(headers.get("Permissions-Policy")).toContain("camera=()");
  });

  it("omits HSTS when disabled", () => {
    expect(toMap(false).has("Strict-Transport-Security")).toBe(false);
  });

  it("formats Permissions-Policy", () => {
    expect(permissionsPolicyValue({ camera: "()", fullscreen: "(self)" })).toBe("camera=(), fullscreen=(self)");
  });
});
