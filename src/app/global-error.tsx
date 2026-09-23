"use client";

export default function GlobalError({ error }: { error: Error & { digest?: string } }) {
  return (
    <html lang="en">
      <body>
        <main>
          <h1>Something went wrong</h1>
          <p>{error.digest ? `Reference: ${error.digest}` : "Please try again later."}</p>
        </main>
      </body>
    </html>
  );
}
