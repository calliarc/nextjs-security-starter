import type { Metadata } from "next";
import { redirect } from "next/navigation";
import { auth, githubEnabled } from "@/auth";
import { githubLoginAction } from "./actions";
import { LoginForm } from "./login-form";

export const metadata: Metadata = { title: "Sign in" };

function safePath(value: string | string[] | undefined): string {
  return typeof value === "string" && value.startsWith("/") && !value.startsWith("//") && !value.includes("\\")
    ? value
    : "/dashboard";
}

export default async function LoginPage({ searchParams }: { searchParams: Promise<Record<string, string | string[] | undefined>> }) {
  const session = await auth();
  const callbackUrl = safePath((await searchParams).callbackUrl);
  if (session?.user) redirect(callbackUrl);

  const demoConfigured = Boolean(process.env.DEMO_USER_EMAIL && process.env.DEMO_USER_PASSWORD_HASH);

  return (
    <>
      <h1>Sign in</h1>
      {!demoConfigured ? (
        <p className="muted">
          No demo user configured. Set <code>DEMO_USER_EMAIL</code> and <code>DEMO_USER_PASSWORD_HASH</code> in{" "}
          <code>.env.local</code> (run <code>npm run hash-password</code>).
        </p>
      ) : null}
      <LoginForm callbackUrl={callbackUrl} />
      {githubEnabled ? (
        <form action={githubLoginAction} className="card">
          <input type="hidden" name="callbackUrl" value={callbackUrl} />
          <button type="submit" className="secondary">
            Sign in with GitHub
          </button>
        </form>
      ) : null}
    </>
  );
}
