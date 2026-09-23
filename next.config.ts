import type { NextConfig } from "next";
import { staticSecurityHeaders } from "./src/lib/security/headers";

const nextConfig: NextConfig = {
  // Do not advertise the framework in an `X-Powered-By` header.
  poweredByHeader: false,
  reactStrictMode: true,
  // Static security headers are also applied here so that responses which
  // bypass `proxy.ts` (e.g. `/_next/static/*`) still carry them. The CSP is
  // nonce-based and is therefore set per request in `src/proxy.ts`.
  async headers() {
    return [
      {
        source: "/:path*",
        headers: staticSecurityHeaders(),
      },
    ];
  },
  experimental: {
    serverActions: {
      // Server Actions already reject requests whose Origin host does not
      // match Host / X-Forwarded-Host. Only add entries here if you run behind
      // a reverse proxy that rewrites the Host header.
      allowedOrigins: [],
      bodySizeLimit: "100kb",
    },
  },
};

export default nextConfig;
