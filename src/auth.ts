import NextAuth, { CredentialsSignin, type NextAuthConfig } from "next-auth";
import Credentials from "next-auth/providers/credentials";
import GitHub from "next-auth/providers/github";
import type { Provider } from "next-auth/providers";
import { loginLimiter } from "@/lib/security/rate-limit";
import { hashPassword, verifyPassword } from "@/lib/security/password";
import { loginSchema } from "@/lib/validation/schemas";

const isProduction = process.env.NODE_ENV === "production";

/** Hash of a random value, used to keep timing uniform for unknown users. */
let dummyHash: Promise<string> | undefined;
function getDummyHash(): Promise<string> {
  dummyHash ??= hashPassword(crypto.randomUUID());
  return dummyHash;
}

class RateLimitedSignin extends CredentialsSignin {
  override code = "rate_limited";
}

/**
 * Demo credentials provider. Replace `findUser` with a database lookup.
 * The user comes from env vars so no credentials are committed to the repo.
 */
async function findUser(email: string): Promise<{ id: string; email: string; passwordHash: string } | null> {
  const demoEmail = process.env.DEMO_USER_EMAIL?.trim().toLowerCase();
  const demoHash = process.env.DEMO_USER_PASSWORD_HASH;
  if (!demoEmail || !demoHash || email !== demoEmail) return null;
  return { id: "demo-user", email: demoEmail, passwordHash: demoHash };
}

const providers: Provider[] = [
  Credentials({
    credentials: {
      email: { type: "email", label: "Email" },
      password: { type: "password", label: "Password" },
    },
    async authorize(credentials) {
      const parsed = loginSchema.safeParse(credentials);
      if (!parsed.success) return null;
      const { email, password } = parsed.data;

      // Per-account limit (per-IP limit is enforced in src/proxy.ts).
      const limit = await loginLimiter.limit(`email:${email}`);
      if (!limit.allowed) throw new RateLimitedSignin();

      const user = await findUser(email);
      // Always run the hash so response time does not reveal whether the account exists.
      const valid = await verifyPassword(password, user?.passwordHash ?? (await getDummyHash()));
      if (!user || !valid) return null;

      await loginLimiter.reset(`email:${email}`);
      return { id: user.id, email: user.email, name: "Demo user" };
    },
  }),
];

export const githubEnabled = Boolean(process.env.AUTH_GITHUB_ID && process.env.AUTH_GITHUB_SECRET);
if (githubEnabled) {
  // Reads AUTH_GITHUB_ID / AUTH_GITHUB_SECRET automatically.
  providers.push(GitHub);
}

export const authConfig = {
  providers,
  pages: { signIn: "/login" },
  session: {
    strategy: "jwt",
    maxAge: 8 * 60 * 60, // 8 hours
    updateAge: 60 * 60, // re-issue at most hourly
  },
  // `__Secure-` prefixed, Secure, HttpOnly, SameSite=Lax cookies in production.
  useSecureCookies: isProduction,
  cookies: {
    sessionToken: {
      options: {
        httpOnly: true,
        sameSite: "lax",
        path: "/",
        secure: isProduction,
      },
    },
  },
  callbacks: {
    jwt({ token, user }) {
      if (user?.id) token.sub = user.id;
      return token;
    },
    session({ session, token }) {
      if (token.sub) session.user.id = token.sub;
      return session;
    },
    // Only allow redirects back to this site after sign-in / sign-out.
    redirect({ url, baseUrl }) {
      if (url.startsWith("/") && !url.startsWith("//")) return `${baseUrl}${url}`;
      try {
        if (new URL(url).origin === baseUrl) return url;
      } catch {
        // fall through
      }
      return baseUrl;
    },
  },
} satisfies NextAuthConfig;

export const { handlers, auth, signIn, signOut } = NextAuth(authConfig);
