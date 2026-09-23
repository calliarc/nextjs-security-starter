/**
 * Content-Security-Policy helpers.
 *
 * A fresh, unpredictable nonce is generated for every request in
 * `src/proxy.ts`. Next.js reads the nonce from the request's CSP header and
 * attaches it to its own framework scripts and inline styles automatically.
 * Because scripts are allowed by nonce + 'strict-dynamic', no host allow-lists
 * are needed for scripts and injected `<script>` tags without the nonce are
 * blocked.
 */

export type CspDirectives = Record<string, string[]>;

export interface CspOptions {
  /** Per-request nonce (base64). */
  nonce: string;
  /** Development mode relaxes the policy just enough for React dev tooling. */
  isDev?: boolean;
  /**
   * Extra sources merged into specific directives, e.g.
   * `{ "img-src": ["https://avatars.githubusercontent.com"] }`.
   */
  extend?: CspDirectives;
  /** Optional reporting endpoint (sets `report-uri`). */
  reportUri?: string;
}

const NONCE_BYTES = 16;

/** Generates a 128-bit cryptographically random nonce encoded as base64. */
export function generateNonce(): string {
  const bytes = new Uint8Array(NONCE_BYTES);
  crypto.getRandomValues(bytes);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

const NONCE_PATTERN = /^[A-Za-z0-9+/]+={0,2}$/;

/** Returns the base CSP directives for a page response. */
export function cspDirectives({ nonce, isDev = false, extend = {} }: CspOptions): CspDirectives {
  if (!NONCE_PATTERN.test(nonce)) {
    throw new Error("Invalid CSP nonce");
  }

  const directives: CspDirectives = {
    "default-src": ["'self'"],
    // 'unsafe-eval' is only needed in development (React uses eval to rebuild
    // server error stacks). It is never emitted in production.
    "script-src": ["'self'", `'nonce-${nonce}'`, "'strict-dynamic'", ...(isDev ? ["'unsafe-eval'"] : [])],
    "style-src": ["'self'", `'nonce-${nonce}'`],
    "img-src": ["'self'", "blob:", "data:"],
    "font-src": ["'self'"],
    "connect-src": ["'self'"],
    "object-src": ["'none'"],
    "base-uri": ["'self'"],
    "form-action": ["'self'"],
    "frame-ancestors": ["'none'"],
    "frame-src": ["'none'"],
    "manifest-src": ["'self'"],
    "worker-src": ["'self'", "blob:"],
  };

  for (const [name, sources] of Object.entries(extend)) {
    const existing = directives[name] ?? [];
    // 'none' cannot be combined with other sources.
    const base = existing.includes("'none'") ? [] : existing;
    directives[name] = Array.from(new Set([...base, ...sources]));
  }

  if (!isDev) {
    directives["upgrade-insecure-requests"] = [];
  }

  return directives;
}

/** Serialises directives into a header value. */
export function serializeCsp(directives: CspDirectives, reportUri?: string): string {
  const parts = Object.entries(directives).map(([name, sources]) =>
    sources.length > 0 ? `${name} ${sources.join(" ")}` : name,
  );
  if (reportUri) parts.push(`report-uri ${reportUri}`);
  return parts.join("; ");
}

/** Builds the full CSP header value for an HTML response. */
export function buildCsp(options: CspOptions): string {
  return serializeCsp(cspDirectives(options), options.reportUri);
}

/**
 * CSP for API / JSON responses: nothing should ever execute or be framed.
 */
export const API_CSP = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'";
