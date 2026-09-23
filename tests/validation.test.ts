import { describe, expect, it, vi } from "vitest";
import { ApiError, handleRouteError } from "@/lib/http/errors";
import { parseJsonBody } from "@/lib/validation/body";
import { loginSchema, messageSchema } from "@/lib/validation/schemas";
import { hashPassword, verifyPassword } from "@/lib/security/password";
// @ts-expect-error - plain JS script without type declarations
import { hash as scriptHash } from "../scripts/hash-password.mjs";

const jsonRequest = (body: string, headers: Record<string, string> = {}) =>
  new Request("https://app.example.com/api/messages", {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body,
  });

describe("schemas", () => {
  it("normalises login email", () => {
    expect(loginSchema.parse({ email: "  Demo@Example.COM ", password: "x" }).email).toBe("demo@example.com");
  });

  it("rejects unknown keys on messages", () => {
    expect(messageSchema.safeParse({ message: "hi", admin: true }).success).toBe(false);
  });
});

describe("parseJsonBody", () => {
  it("parses valid bodies", async () => {
    await expect(parseJsonBody(jsonRequest('{"message":" hi "}'), messageSchema)).resolves.toEqual({ message: "hi" });
  });

  it("enforces content type, size and JSON syntax", async () => {
    await expect(parseJsonBody(jsonRequest("{}", { "content-type": "text/plain" }), messageSchema)).rejects.toMatchObject({ status: 415 });
    await expect(parseJsonBody(jsonRequest(JSON.stringify({ message: "x".repeat(100) })), messageSchema, 50)).rejects.toMatchObject({ status: 413 });
    await expect(parseJsonBody(jsonRequest("{not json"), messageSchema)).rejects.toMatchObject({ status: 400 });
  });
});

describe("handleRouteError", () => {
  it("returns validation issues without internals", async () => {
    const error = messageSchema.safeParse({ message: "" }).error;
    const res = handleRouteError(error);
    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.error.code).toBe("invalid_request");
    expect(body.error.issues[0].path).toBe("message");
  });

  it("maps ApiError to its status", async () => {
    const res = handleRouteError(new ApiError(401, "unauthorized", "Authentication required."));
    expect(res.status).toBe(401);
    expect(res.headers.get("cache-control")).toBe("no-store");
  });

  it("hides unexpected errors behind a generic 500", async () => {
    const spy = vi.spyOn(console, "error").mockImplementation(() => {});
    const res = handleRouteError(new Error("internal-detail-xyz at /srv/app/db.ts:42"));
    const text = await res.text();
    expect(res.status).toBe(500);
    expect(text).not.toContain("internal-detail-xyz");
    expect(text).not.toContain("db.ts");
    expect(JSON.parse(text).error.requestId).toMatch(/^[0-9a-f-]{36}$/);
    spy.mockRestore();
  });
});

describe("password hashing", () => {
  it("round-trips and rejects wrong passwords", async () => {
    const stored = await hashPassword("correct horse battery staple");
    expect(stored.startsWith("scrypt:16384:8:1:")).toBe(true);
    expect(stored).not.toContain("$");
    expect(await verifyPassword("correct horse battery staple", stored)).toBe(true);
    expect(await verifyPassword("wrong", stored)).toBe(false);
    expect(await verifyPassword("x", "garbage")).toBe(false);
  });

  it("accepts hashes produced by scripts/hash-password.mjs", async () => {
    expect(await verifyPassword("from the cli script", scriptHash("from the cli script"))).toBe(true);
  });
});
