import jwt from "jsonwebtoken";
import crypto from "crypto";
import { env } from "../config/env";
import type { Role } from "@prisma/client";

export interface AccessTokenPayload {
  sub: string; // userId
  role: Role;
  sid: string; // session id, lets us revoke a specific session's access tokens
}

export function signAccessToken(payload: AccessTokenPayload): string {
  return jwt.sign(payload, env.JWT_ACCESS_SECRET, {
    expiresIn: env.JWT_ACCESS_TTL,
    issuer: "inspir-connect",
  });
}

export function verifyAccessToken(token: string): AccessTokenPayload {
  return jwt.verify(token, env.JWT_ACCESS_SECRET, { issuer: "inspir-connect" }) as AccessTokenPayload;
}

// Refresh tokens are opaque random strings, NOT JWTs. We store only a SHA-256
// hash of them in the Session table, so a database leak alone can't be used
// to forge a working refresh token (same principle as password hashing).
export function generateRefreshToken(): string {
  return crypto.randomBytes(48).toString("base64url");
}

export function hashRefreshToken(token: string): string {
  return crypto.createHash("sha256").update(token).digest("hex");
}

export function refreshTtlMs(): number {
  const ttl = env.JWT_REFRESH_TTL; // e.g. "30d"
  const match = /^(\d+)([smhd])$/.exec(ttl);
  if (!match) return 30 * 24 * 60 * 60 * 1000;
  const [, num, unit] = match;
  const n = Number(num);
  const multipliers: Record<string, number> = {
    s: 1000,
    m: 60 * 1000,
    h: 60 * 60 * 1000,
    d: 24 * 60 * 60 * 1000,
  };
  return n * multipliers[unit];
}
