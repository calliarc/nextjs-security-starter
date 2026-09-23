"use server";

import { AuthError } from "next-auth";
import { signIn } from "@/auth";
import { loginSchema } from "@/lib/validation/schemas";

export interface LoginState {
  error?: string;
}

/** Only allow same-site relative redirect targets (prevents open redirects). */
function safeCallbackUrl(value: FormDataEntryValue | null): string {
  if (typeof value !== "string" || !value.startsWith("/") || value.startsWith("//") || value.includes("\\")) {
    return "/dashboard";
  }
  return value;
}

/**
 * Server Action: Next.js rejects the call if the Origin header does not match
 * the Host (built-in CSRF protection). Per-IP rate limiting for POST /login is
 * applied in src/proxy.ts; per-account limiting happens in `authorize`.
 */
export async function loginAction(_prev: LoginState, formData: FormData): Promise<LoginState> {
  const parsed = loginSchema.safeParse({
    email: formData.get("email"),
    password: formData.get("password"),
  });
  if (!parsed.success) {
    return { error: "Enter a valid email and password." };
  }

  try {
    await signIn("credentials", {
      ...parsed.data,
      redirectTo: safeCallbackUrl(formData.get("callbackUrl")),
    });
    return {};
  } catch (error) {
    if (error instanceof AuthError) {
      if (error.type === "CredentialsSignin" && "code" in error && error.code === "rate_limited") {
        return { error: "Too many attempts. Please wait a minute and try again." };
      }
      // Same message for unknown user and wrong password (no account enumeration).
      return { error: "Invalid email or password." };
    }
    // Re-throw Next.js redirect / unexpected errors.
    throw error;
  }
}

export async function githubLoginAction(formData: FormData): Promise<void> {
  await signIn("github", { redirectTo: safeCallbackUrl(formData.get("callbackUrl")) });
}
