/**
 * Central security-header configuration.
 *
 * Every non-CSP security header lives here so there is exactly one place to
 * review or change them. They are applied twice on purpose:
 *   1. `next.config.ts` -> `headers()` covers every route, including static
 *      assets that skip the proxy.
 *   2. `src/proxy.ts` sets them on responses it creates itself (redirects,
 *      429s) where `next.config.ts` headers are not guaranteed.
 * The nonce-based Content-Security-Policy is built per request in the proxy
 * (see `csp.ts`).
 */

export interface HeaderEntry {
  key: string;
  value: string;
}

export interface SecurityHeaderOptions {
  /** Emit HSTS. Defaults to true in production. */
  hsts?: boolean;
  /**
   * Add `preload` to HSTS. Only enable after reading https://hstspreload.org/
   * because removal from the preload list is slow.
   */
  hstsPreload?: boolean;
}

/** Two years, as recommended by hstspreload.org. */
export const HSTS_MAX_AGE = 63_072_000;

/** Browser features this app does not use are disabled outright. */
export const PERMISSIONS_POLICY: Record<string, string> = {
  accelerometer: "()",
  autoplay: "()",
  camera: "()",
  "display-capture": "()",
  geolocation: "()",
  gyroscope: "()",
  magnetometer: "()",
  microphone: "()",
  midi: "()",
  payment: "()",
  usb: "()",
  "browsing-topics": "()",
  "interest-cohort": "()",
};

export function permissionsPolicyValue(policy: Record<string, string> = PERMISSIONS_POLICY): string {
  return Object.entries(policy)
    .map(([feature, allow]) => `${feature}=${allow}`)
    .join(", ");
}

export function staticSecurityHeaders(options: SecurityHeaderOptions = {}): HeaderEntry[] {
  const hsts = options.hsts ?? process.env.NODE_ENV === "production";
  const headers: HeaderEntry[] = [
    { key: "X-Content-Type-Options", value: "nosniff" },
    { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
    { key: "Permissions-Policy", value: permissionsPolicyValue() },
    // Legacy clickjacking protection; CSP `frame-ancestors 'none'` is the
    // modern equivalent and is set in the CSP.
    { key: "X-Frame-Options", value: "DENY" },
    { key: "Cross-Origin-Opener-Policy", value: "same-origin" },
    { key: "Cross-Origin-Resource-Policy", value: "same-origin" },
    { key: "Origin-Agent-Cluster", value: "?1" },
    { key: "X-DNS-Prefetch-Control", value: "off" },
    { key: "X-Permitted-Cross-Domain-Policies", value: "none" },
  ];

  if (hsts) {
    headers.push({
      key: "Strict-Transport-Security",
      value: `max-age=${HSTS_MAX_AGE}; includeSubDomains${options.hstsPreload ? "; preload" : ""}`,
    });
  }

  return headers;
}

/** Applies the static headers (and optionally a CSP) to a Headers object. */
export function applySecurityHeaders(target: Headers, csp?: string, options?: SecurityHeaderOptions): Headers {
  for (const { key, value } of staticSecurityHeaders(options)) {
    target.set(key, value);
  }
  if (csp) target.set("Content-Security-Policy", csp);
  return target;
}
