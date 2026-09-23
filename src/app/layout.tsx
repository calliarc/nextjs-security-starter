import type { Metadata } from "next";
import { connection } from "next/server";
import Link from "next/link";
import "./globals.css";

export const metadata: Metadata = {
  title: "Next.js Security Starter",
  description: "Next.js template with secure headers, rate limiting, CSRF protection and auth set up correctly.",
  referrer: "strict-origin-when-cross-origin",
};

export default async function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  // Nonce-based CSP requires dynamic rendering: every response gets a fresh
  // nonce, which Next.js applies to its scripts automatically.
  await connection();

  return (
    <html lang="en">
      <body>
        <header className="site-header">
          <Link href="/" className="brand">
            Next.js Security Starter
          </Link>
          <nav>
            <Link href="/dashboard">Dashboard</Link>
            <Link href="/login">Sign in</Link>
          </nav>
        </header>
        <main>{children}</main>
        <footer className="site-footer">
          Built by <a href="https://www.calliarc.com/">CalliArc</a>
        </footer>
      </body>
    </html>
  );
}
