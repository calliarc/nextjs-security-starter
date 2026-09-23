import { randomBytes, scrypt, timingSafeEqual, type ScryptOptions } from "node:crypto";

/**
 * scrypt password hashing (Node's built-in, no native deps).
 * Format: `scrypt:N:r:p:<salt base64url>:<hash base64url>` - no `$` so it is
 * safe inside `.env` files (Next.js expands `$VAR`).
 *
 * Keep parameters in sync with `scripts/hash-password.mjs`.
 */
const N = 16384;
const R = 8;
const P = 1;
const KEY_LENGTH = 64;
const MAX_PASSWORD_LENGTH = 256;

function scryptAsync(password: string, salt: Buffer, keyLength: number, options: ScryptOptions): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    scrypt(password, salt, keyLength, options, (error, derived) => (error ? reject(error) : resolve(derived)));
  });
}

export async function hashPassword(password: string): Promise<string> {
  if (password.length === 0 || password.length > MAX_PASSWORD_LENGTH) {
    throw new Error("Invalid password length");
  }
  const salt = randomBytes(16);
  const hash = await scryptAsync(password, salt, KEY_LENGTH, { N, r: R, p: P });
  return ["scrypt", N, R, P, salt.toString("base64url"), hash.toString("base64url")].join(":");
}

export async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const parts = stored.split(":");
  if (parts.length !== 6 || parts[0] !== "scrypt") return false;
  const [, n, r, p, saltB64, hashB64] = parts as [string, string, string, string, string, string];
  const cost = Number(n);
  const blockSize = Number(r);
  const parallelization = Number(p);
  if (![cost, blockSize, parallelization].every(Number.isSafeInteger) || cost > 2 ** 20) return false;
  if (password.length > MAX_PASSWORD_LENGTH) return false;

  const expected = Buffer.from(hashB64, "base64url");
  if (expected.length === 0) return false;
  const actual = await scryptAsync(password, Buffer.from(saltB64, "base64url"), expected.length, {
    N: cost,
    r: blockSize,
    p: parallelization,
    maxmem: 256 * cost * blockSize,
  });
  return timingSafeEqual(actual, expected);
}
