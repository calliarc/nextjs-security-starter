"use server";

import { auth, signOut } from "@/auth";
import { noteSchema } from "@/lib/validation/schemas";

export interface NoteState {
  ok?: boolean;
  error?: string;
  saved?: string;
}

/**
 * Server Action example. CSRF: Next.js only accepts POST for Server Actions
 * and rejects calls whose Origin host differs from Host / X-Forwarded-Host.
 * Authorization must still be checked inside every action: the proxy
 * matcher is not a security boundary for actions.
 */
export async function saveNoteAction(_prev: NoteState, formData: FormData): Promise<NoteState> {
  const session = await auth();
  if (!session?.user) return { error: "Please sign in again." };

  const parsed = noteSchema.safeParse({ note: formData.get("note") });
  if (!parsed.success) {
    return { error: parsed.error.issues[0]?.message ?? "Invalid note." };
  }

  // Persist parsed.data.note for session.user.id here.
  return { ok: true, saved: parsed.data.note };
}

export async function signOutAction(): Promise<void> {
  await signOut({ redirectTo: "/" });
}
