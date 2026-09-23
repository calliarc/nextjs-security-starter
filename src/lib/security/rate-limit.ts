/**
 * Token-bucket rate limiting with a pluggable store.
 *
 * Each key (e.g. `login:ip:203.0.113.7`) owns a bucket holding up to
 * `capacity` tokens. A request consumes one token; tokens refill continuously
 * at `refillPerSecond`. This allows short bursts while enforcing an average
 * rate.
 *
 * The default `MemoryStore` is per-process: it resets on restart and is not
 * shared between instances or serverless invocations. In production, provide
 * a shared store (e.g. Redis / Upstash) that implements `RateLimitStore`
 * atomically - see README "Rate limiting in production".
 */

export interface RateLimitPolicy {
  /** Maximum burst size (bucket size). */
  capacity: number;
  /** Tokens added back per second. */
  refillPerSecond: number;
}

export interface BucketState {
  tokens: number;
  /** Epoch milliseconds of the last refill calculation. */
  updatedAt: number;
}

export interface RateLimitResult {
  allowed: boolean;
  limit: number;
  /** Whole tokens left after this request. */
  remaining: number;
  /** Seconds until at least one token is available (0 when allowed). */
  retryAfterSeconds: number;
}

/**
 * A store must perform read-refill-consume-write atomically for a key.
 * For Redis this is typically a small Lua script (EVALSHA) or Upstash's
 * `@upstash/ratelimit` package wrapped in this interface.
 */
export interface RateLimitStore {
  consume(key: string, policy: RateLimitPolicy, now: number, cost?: number): Promise<RateLimitResult>;
  reset(key: string): Promise<void>;
}

function assertPolicy(policy: RateLimitPolicy): void {
  if (!(policy.capacity > 0) || !(policy.refillPerSecond > 0)) {
    throw new Error("Rate limit policy requires positive capacity and refillPerSecond");
  }
}

/**
 * Pure token-bucket step. Exported so custom stores (and tests) can reuse the
 * exact same maths.
 */
export function takeToken(
  state: BucketState | undefined,
  policy: RateLimitPolicy,
  now: number,
  cost = 1,
): { state: BucketState; result: RateLimitResult } {
  assertPolicy(policy);
  const previous = state ?? { tokens: policy.capacity, updatedAt: now };
  const elapsedSeconds = Math.max(0, now - previous.updatedAt) / 1000;
  const refilled = Math.min(policy.capacity, previous.tokens + elapsedSeconds * policy.refillPerSecond);

  if (refilled >= cost) {
    const tokens = refilled - cost;
    return {
      state: { tokens, updatedAt: now },
      result: { allowed: true, limit: policy.capacity, remaining: Math.floor(tokens), retryAfterSeconds: 0 },
    };
  }

  const deficit = cost - refilled;
  return {
    state: { tokens: refilled, updatedAt: now },
    result: {
      allowed: false,
      limit: policy.capacity,
      remaining: 0,
      retryAfterSeconds: Math.max(1, Math.ceil(deficit / policy.refillPerSecond)),
    },
  };
}

export interface MemoryStoreOptions {
  /** Upper bound on tracked keys to avoid unbounded memory growth. */
  maxKeys?: number;
}

/** In-memory, single-process store. Suitable for development and single-instance deployments. */
export class MemoryStore implements RateLimitStore {
  private readonly buckets = new Map<string, BucketState>();
  private readonly maxKeys: number;

  constructor(options: MemoryStoreOptions = {}) {
    this.maxKeys = options.maxKeys ?? 10_000;
  }

  get size(): number {
    return this.buckets.size;
  }

  async consume(key: string, policy: RateLimitPolicy, now: number, cost = 1): Promise<RateLimitResult> {
    const current = this.buckets.get(key);
    const { state, result } = takeToken(current, policy, now, cost);
    // Re-insert so Map iteration order approximates LRU.
    this.buckets.delete(key);
    this.buckets.set(key, state);
    this.evict();
    return result;
  }

  async reset(key: string): Promise<void> {
    this.buckets.delete(key);
  }

  private evict(): void {
    while (this.buckets.size > this.maxKeys) {
      const oldest = this.buckets.keys().next().value;
      if (oldest === undefined) break;
      this.buckets.delete(oldest);
    }
  }
}

export class RateLimiter {
  constructor(
    readonly name: string,
    readonly policy: RateLimitPolicy,
    private readonly store: RateLimitStore,
    private readonly clock: () => number = Date.now,
  ) {
    assertPolicy(policy);
  }

  limit(identifier: string, cost = 1): Promise<RateLimitResult> {
    return this.store.consume(`${this.name}:${identifier}`, this.policy, this.clock(), cost);
  }

  reset(identifier: string): Promise<void> {
    return this.store.reset(`${this.name}:${identifier}`);
  }
}

/** Standard rate-limit response headers (IETF draft `RateLimit-*` + `Retry-After`). */
export function rateLimitHeaders(result: RateLimitResult): Record<string, string> {
  const headers: Record<string, string> = {
    "RateLimit-Limit": String(result.limit),
    "RateLimit-Remaining": String(result.remaining),
  };
  if (!result.allowed) headers["Retry-After"] = String(result.retryAfterSeconds);
  return headers;
}

// ---------------------------------------------------------------------------
// Shared store + preset limiters
// ---------------------------------------------------------------------------

const globalForRateLimit = globalThis as unknown as { __rateLimitStore?: RateLimitStore };

/**
 * Swap this for a Redis/Upstash-backed store in production. Kept on
 * `globalThis` so hot reloads in development do not reset the buckets.
 */
export const defaultStore: RateLimitStore = (globalForRateLimit.__rateLimitStore ??= new MemoryStore());

/** Login attempts: burst of 5, then one attempt every 12 seconds (5/min). */
export const LOGIN_POLICY: RateLimitPolicy = { capacity: 5, refillPerSecond: 5 / 60 };
/** General API traffic: burst of 30, sustained 1 request/second. */
export const API_POLICY: RateLimitPolicy = { capacity: 30, refillPerSecond: 1 };

export const loginLimiter = new RateLimiter("login", LOGIN_POLICY, defaultStore);
export const apiLimiter = new RateLimiter("api", API_POLICY, defaultStore);
