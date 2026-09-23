import type { Metadata } from "next";
import { redirect } from "next/navigation";
import { auth } from "@/auth";
import { signOutAction } from "./actions";
import { MessageForm } from "./message-form";
import { NoteForm } from "./note-form";

export const metadata: Metadata = { title: "Dashboard" };

export default async function DashboardPage() {
  // The proxy only does an optimistic cookie check; this is the real one.
  const session = await auth();
  if (!session?.user) redirect("/login?callbackUrl=/dashboard");

  return (
    <>
      <h1>Dashboard</h1>
      <p>
        Signed in as <strong>{session.user.email ?? session.user.name}</strong>.
      </p>
      <section className="card">
        <NoteForm />
      </section>
      <section className="card">
        <MessageForm />
      </section>
      <form action={signOutAction}>
        <button type="submit" className="secondary">
          Sign out
        </button>
      </form>
    </>
  );
}
