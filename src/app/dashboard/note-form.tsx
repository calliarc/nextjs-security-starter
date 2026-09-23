"use client";

import { useActionState } from "react";
import { saveNoteAction, type NoteState } from "./actions";

export function NoteForm() {
  const [state, formAction, pending] = useActionState<NoteState, FormData>(saveNoteAction, {});
  return (
    <form action={formAction}>
      <label>
        Note (Server Action)
        <input name="note" maxLength={280} required />
      </label>
      <button type="submit" disabled={pending}>
        Save note
      </button>
      {state.error ? <p className="error" role="alert">{state.error}</p> : null}
      {state.ok ? <p className="success">Saved: {state.saved}</p> : null}
    </form>
  );
}
