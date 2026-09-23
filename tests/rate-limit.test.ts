import { describe, expect, it } from "vitest";
import { MemoryStore, RateLimiter, rateLimitHeaders, takeToken, type RateLimitStore } from "@/lib/security/rate-limit";

const policy = { capacity: 3, refillPerSecond: 1 };

function limiter(store: RateLimitStore = new MemoryStore()) {
  let now = 1_000_000;
  const rl = new RateLimiter("test", policy, store, () => now);
  return { rl, advance: (ms: number) => (now += ms) };
}

describe("takeToken", () => {
  it("starts with a full bucket", () => {
    const { result, state } = takeToken(undefined, policy, 0);
    expect(result).toEqual({ allowed: true, limit: 3, remaining: 2, retryAfterSeconds: 0 });
    expect(state.tokens).toBe(2);
  });

  it("never refills above capacity", () => {
    const { state } = takeToken({ tokens: 0, updatedAt: 0 }, policy, 3_600_000);
    expect(state.tokens).toBe(2);
  });

  it("computes retry-after from the deficit", () => {
    const slow = { capacity: 1, refillPerSecond: 0.1 };
    const { result } = takeToken({ tokens: 0, updatedAt: 0 }, slow, 0);
    expect(result.allowed).toBe(false);
    expect(result.retryAfterSeconds).toBe(10);
  });

  it("rejects invalid policies", () => {
    expect(() => takeToken(undefined, { capacity: 0, refillPerSecond: 1 }, 0)).toThrow();
    expect(() => takeToken(undefined, { capacity: 1, refillPerSecond: 0 }, 0)).toThrow();
  });
});

describe("RateLimiter + MemoryStore", () => {
  it("allows a burst up to capacity then blocks", async () => {
    const { rl } = limiter();
    const results = await Promise.all([1, 2, 3, 4].map(() => rl.limit("1.2.3.4")));
    expect(results.map((r) => r.allowed)).toEqual([true, true, true, false]);
    expect(results[3]?.retryAfterSeconds).toBe(1);
  });

  it("refills over time", async () => {
    const { rl, advance } = limiter();
    for (let i = 0; i < 3; i++) await rl.limit("k");
    expect((await rl.limit("k")).allowed).toBe(false);
    advance(1000);
    expect((await rl.limit("k")).allowed).toBe(true);
    expect((await rl.limit("k")).allowed).toBe(false);
  });

  it("isolates keys and limiter names", async () => {
    const store = new MemoryStore();
    const a = new RateLimiter("a", { capacity: 1, refillPerSecond: 1 }, store, () => 0);
    const b = new RateLimiter("b", { capacity: 1, refillPerSecond: 1 }, store, () => 0);
    expect((await a.limit("x")).allowed).toBe(true);
    expect((await a.limit("x")).allowed).toBe(false);
    expect((await a.limit("y")).allowed).toBe(true);
    expect((await b.limit("x")).allowed).toBe(true);
  });

  it("reset clears a bucket", async () => {
    const { rl } = limiter();
    for (let i = 0; i < 3; i++) await rl.limit("k");
    await rl.reset("k");
    expect((await rl.limit("k")).remaining).toBe(2);
  });

  it("bounds memory with LRU eviction", async () => {
    const store = new MemoryStore({ maxKeys: 2 });
    for (const key of ["a", "b", "c"]) await store.consume(key, policy, 0);
    expect(store.size).toBe(2);
    // "a" was evicted, so it starts with a full bucket again.
    expect((await store.consume("a", policy, 0)).remaining).toBe(2);
  });

  it("accepts any store implementing the interface", async () => {
    const calls: string[] = [];
    const store: RateLimitStore = {
      async consume(key) {
        calls.push(key);
        return { allowed: false, limit: 1, remaining: 0, retryAfterSeconds: 5 };
      },
      async reset() {},
    };
    const rl = new RateLimiter("custom", policy, store);
    expect((await rl.limit("id")).allowed).toBe(false);
    expect(calls).toEqual(["custom:id"]);
  });
});

describe("rateLimitHeaders", () => {
  it("adds Retry-After only when blocked", () => {
    expect(rateLimitHeaders({ allowed: true, limit: 5, remaining: 4, retryAfterSeconds: 0 })).toEqual({
      "RateLimit-Limit": "5",
      "RateLimit-Remaining": "4",
    });
    expect(rateLimitHeaders({ allowed: false, limit: 5, remaining: 0, retryAfterSeconds: 7 })["Retry-After"]).toBe("7");
  });
});
