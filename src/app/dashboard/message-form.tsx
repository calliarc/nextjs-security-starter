"use client";

import { useState, type FormEvent } from "react";

type Status = { kind: "idle" } | { kind: "ok"; text: string } | { kind: "error"; text: string };

async function getCsrfToken(): Promise<string> {
  const response = await fetch("/api/csrf", { credentials: "same-origin", cache: "no-store" });
  if (!response.ok) throw new Error("Could not obtain CSRF token");
  const body = (await response.json()) as { token: string };
  return body.token;
}

/** Calls a Route Handler with the double-submit CSRF token. */
export function MessageForm() {
  const [status, setStatus] = useState<Status>({ kind: "idle" });
  const [pending, setPending] = useState(false);

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const message = String(new FormData(form).get("message") ?? "");
    setPending(true);
    try {
      const token = await getCsrfToken();
      const response = await fetch("/api/messages", {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json", "x-csrf-token": token },
        body: JSON.stringify({ message }),
      });
      const body = (await response.json()) as { error?: { message: string }; length?: number };
      if (response.ok) {
        setStatus({ kind: "ok", text: `Accepted (${body.length} characters).` });
        form.reset();
      } else {
        setStatus({ kind: "error", text: body.error?.message ?? "Request failed." });
      }
    } catch {
      setStatus({ kind: "error", text: "Request failed." });
    } finally {
      setPending(false);
    }
  }

  return (
    <form onSubmit={onSubmit}>
      <label>
        Message (Route Handler + CSRF token)
        <textarea name="message" rows={3} maxLength={500} required />
      </label>
      <button type="submit" disabled={pending}>
        Send
      </button>
      {status.kind === "ok" ? <p className="success">{status.text}</p> : null}
      {status.kind === "error" ? <p className="error" role="alert">{status.text}</p> : null}
    </form>
  );
}
