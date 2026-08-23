import argon2 from "argon2";

// argon2id is the current OWASP-recommended variant: resistant to both
// GPU cracking and side-channel attacks. Never switch to bcrypt/md5/sha for new code.
const ARGON2_OPTIONS = {
  type: argon2.argon2id,
  memoryCost: 19456, // ~19 MB, OWASP minimum recommendation
  timeCost: 2,
  parallelism: 1,
};

export async function hashPassword(plain: string): Promise<string> {
  return argon2.hash(plain, ARGON2_OPTIONS);
}

export async function verifyPassword(hash: string, plain: string): Promise<boolean> {
  try {
    return await argon2.verify(hash, plain);
  } catch {
    // Malformed hash or verification error — treat as failed auth, never throw to caller.
    return false;
  }
}

// Minimum password policy, enforced server-side (never trust client-side only).
export function isPasswordStrongEnough(password: string): { ok: boolean; reason?: string } {
  if (password.length < 10) return { ok: false, reason: "Password must be at least 10 characters." };
  if (!/[a-z]/.test(password)) return { ok: false, reason: "Password must include a lowercase letter." };
  if (!/[A-Z]/.test(password)) return { ok: false, reason: "Password must include an uppercase letter." };
  if (!/[0-9]/.test(password)) return { ok: false, reason: "Password must include a number." };
  return { ok: true };
}
