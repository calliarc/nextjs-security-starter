import { describe, expect, it } from "vitest";
import {
  CSRF_HEADER,
  createCsrfToken,
  csrfCookieName,
  getCsrfSecret,
  timingSafeEqual,
  validateDoubleSubmit,
  verifyCsrf,
  verifyCsrfToken,
  verifyOrigin,
} from "@/lib/security/csrf";

// Generated per run; never a real secret.
const secret = crypto.randomUUID() + crypto.randomUUID();
const otherSecret = crypto.randomUUID() + crypto.randomUUID();

function req(method: string, headers: Record<string, string>, url = "https://app.example.com/api/messages") {
  return new Request(url, { method, headers: { host: "app.example.com", ...headers } });
}

describe("verifyOrigin", () => {
  it("allows safe methods without an Origin", () => {
    expect(verifyOrigin(req("GET", {})).ok).toBe(true);
  });

  it("accepts same-origin POST", () => {
    expect(verifyOrigin(req("POST", { origin: "https://app.example.com" })).ok).toBe(true);
  });

  it("rejects cross-origin POST", () => {
    expect(verifyOrigin(req("POST", { origin: "https://evil.example" }))).toEqual({ ok: false, reason: "origin mismatch" });
  });

  it("rejects look-alike hosts and scheme downgrades", () => {
    expect(verifyOrigin(req("POST", { origin: "https://app.example.com.evil.example" })).ok).toBe(false);
    expect(verifyOrigin(req("POST", { origin: "http://app.example.com" })).ok).toBe(false);
  });

  it("rejects missing or opaque Origin", () => {
    expect(verifyOrigin(req("POST", {})).ok).toBe(false);
    expect(verifyOrigin(req("POST", { origin: "null" })).ok).toBe(false);
  });

  it("falls back to Referer", () => {
    expect(verifyOrigin(req("POST", { referer: "https://app.example.com/dashboard" })).ok).toBe(true);
    expect(verifyOrigin(req("POST", { referer: "https://evil.example/x" })).ok).toBe(false);
  });

  it("rejects Sec-Fetch-Site: cross-site even with a matching Origin", () => {
    expect(verifyOrigin(req("POST", { origin: "https://app.example.com", "sec-fetch-site": "cross-site" })).ok).toBe(false);
  });

  it("honours the allow-list", () => {
    const r = req("POST", { origin: "https://admin.example.com" });
    expect(verifyOrigin(r).ok).toBe(false);
    expect(verifyOrigin(r, { allowedOrigins: ["https://admin.example.com/"] }).ok).toBe(true);
  });

  it("ignores X-Forwarded-Host unless trusted", () => {
    const r = req("POST", { origin: "https://evil.example", "x-forwarded-host": "evil.example" });
    expect(verifyOrigin(r).ok).toBe(false);
    const proxied = new Request("http://internal:3000/api/messages", {
      method: "POST",
      headers: {
        host: "internal:3000",
        origin: "https://app.example.com",
        "x-forwarded-host": "app.example.com",
        "x-forwarded-proto": "https",
      },
    });
    expect(verifyOrigin(proxied).ok).toBe(false);
    expect(verifyOrigin(proxied, { trustForwardedHeaders: true }).ok).toBe(true);
  });
});

describe("CSRF tokens", () => {
  it("creates verifiable, unique tokens", async () => {
    const a = await createCsrfToken(secret);
    const b = await createCsrfToken(secret);
    expect(a).not.toBe(b);
    expect(a).toMatch(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
    expect(await verifyCsrfToken(a, secret)).toBe(true);
  });

  it("rejects tampered, foreign or malformed tokens", async () => {
    const token = await createCsrfToken(secret);
    const [value, sig] = token.split(".");
    expect(await verifyCsrfToken(`${value}x.${sig}`, secret)).toBe(false);
    expect(await verifyCsrfToken(token, otherSecret)).toBe(false);
    expect(await verifyCsrfToken("", secret)).toBe(false);
    expect(await verifyCsrfToken("abc", secret)).toBe(false);
    expect(await verifyCsrfToken(`${token}.extra`, secret)).toBe(false);
  });

  it("requires a strong secret", async () => {
    await expect(createCsrfToken("short")).rejects.toThrow();
    expect(() => getCsrfSecret({})).toThrow();
    expect(getCsrfSecret({ AUTH_SECRET: secret })).toBe(secret);
    expect(getCsrfSecret({ AUTH_SECRET: secret, CSRF_SECRET: otherSecret })).toBe(otherSecret);
  });

  it("validates the double-submit pair", async () => {
    const token = await createCsrfToken(secret);
    const other = await createCsrfToken(secret);
    expect(await validateDoubleSubmit(token, token, secret)).toBe(true);
    expect(await validateDoubleSubmit(token, other, secret)).toBe(false);
    expect(await validateDoubleSubmit(token, null, secret)).toBe(false);
    expect(await validateDoubleSubmit(null, token, secret)).toBe(false);
  });

  it("timingSafeEqual compares correctly", () => {
    expect(timingSafeEqual("abc", "abc")).toBe(true);
    expect(timingSafeEqual("abc", "abd")).toBe(false);
    expect(timingSafeEqual("abc", "abcd")).toBe(false);
  });
});

describe("verifyCsrf (full request check)", () => {
  const cookieName = csrfCookieName(false);

  it("passes with same origin, cookie and header", async () => {
    const token = await createCsrfToken(secret);
    const r = req("POST", {
      origin: "https://app.example.com",
      cookie: `other=1; ${cookieName}=${token}`,
      [CSRF_HEADER]: token,
    });
    expect(await verifyCsrf(r, { secret, cookieName })).toEqual({ ok: true });
  });

  it("fails without the header token", async () => {
    const token = await createCsrfToken(secret);
    const r = req("POST", { origin: "https://app.example.com", cookie: `${cookieName}=${token}` });
    expect((await verifyCsrf(r, { secret, cookieName })).ok).toBe(false);
  });

  it("fails cross-origin even with a valid token", async () => {
    const token = await createCsrfToken(secret);
    const r = req("POST", { origin: "https://evil.example", cookie: `${cookieName}=${token}`, [CSRF_HEADER]: token });
    expect((await verifyCsrf(r, { secret, cookieName })).ok).toBe(false);
  });

  it("uses a __Host- cookie in production", () => {
    expect(csrfCookieName(true)).toBe("__Host-csrf");
  });
});
