#!/usr/bin/env node
// Prints an scrypt hash for DEMO_USER_PASSWORD_HASH.
// Usage: npm run hash-password            (prompts, input hidden)
//        echo -n 'pw' | npm run hash-password --silent
// Parameters must match src/lib/security/password.ts.
import { randomBytes, scryptSync } from "node:crypto";
import { createInterface } from "node:readline";

export function hash(password) {
  const salt = randomBytes(16);
  const derived = scryptSync(password, salt, 64, { N: 16384, r: 8, p: 1 });
  return ["scrypt", 16384, 8, 1, salt.toString("base64url"), derived.toString("base64url")].join(":");
}

async function readPassword() {
  if (!process.stdin.isTTY) {
    let data = "";
    for await (const chunk of process.stdin) data += chunk;
    return data.replace(/\r?\n$/, "");
  }
  const rl = createInterface({ input: process.stdin, output: process.stdout, terminal: true });
  process.stdout.write("Password: ");
  // Hide typed characters.
  rl._writeToOutput = () => {};
  const answer = await new Promise((resolve) => rl.question("", resolve));
  rl.close();
  process.stdout.write("\n");
  return answer;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const password = await readPassword();
  if (password.length < 12) {
    console.error("Use at least 12 characters.");
    process.exit(1);
  }
  console.log(hash(password));
}
