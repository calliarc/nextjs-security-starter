"use client";

/**
 * Route-level error boundary. In production Next.js strips server error
 * messages and only passes an opaque `digest`, which can be matched against
 * server logs. Never render `error.message` or `error.stack` here.
 */
export default function ErrorPage({ error, reset }: { error: Error & { digest?: string }; reset: () => void }) {
  return (
    <>
      <h1>Something went wrong</h1>
      <p className="muted">
        Please try again.{error.digest ? ` Reference: ${error.digest}` : null}
      </p>
      <button type="button" onClick={reset}>
        Try again
      </button>
    </>
  );
}
