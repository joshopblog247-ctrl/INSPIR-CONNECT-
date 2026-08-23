import crypto from "crypto";
import { prisma } from "../lib/prisma";
import { hashPassword, verifyPassword, isPasswordStrongEnough } from "../lib/password";
import {
  signAccessToken,
  generateRefreshToken,
  hashRefreshToken,
  refreshTtlMs,
} from "../lib/jwt";
import { logger } from "../lib/logger";
import type { AuthProvider } from "@prisma/client";

const MAX_FAILED_LOGINS = 5;
const LOCKOUT_MINUTES = 15;

export class AuthError extends Error {
  constructor(public code: string, message: string, public status = 400) {
    super(message);
  }
}

interface RegisterInput {
  method: "email" | "phone";
  email?: string;
  phone?: string;
  password: string;
  fullName: string;
  username: string;
}

interface DeviceContext {
  ipAddress?: string;
  userAgent?: string;
  deviceLabel?: string;
}

// Exported so other auth flows (Google sign-in) can issue a session without
// duplicating token/session creation logic.
export async function issueSession(userId: string, role: string, device: DeviceContext) {
  const sessionId = crypto.randomUUID();
  const refreshToken = generateRefreshToken();

  await prisma.session.create({
    data: {
      id: sessionId,
      userId,
      refreshTokenHash: hashRefreshToken(refreshToken),
      deviceLabel: device.deviceLabel,
      ipAddress: device.ipAddress,
      userAgent: device.userAgent,
      expiresAt: new Date(Date.now() + refreshTtlMs()),
    },
  });

  const accessToken = signAccessToken({ sub: userId, role: role as any, sid: sessionId });
  return { accessToken, refreshToken };
}

export async function register(input: RegisterInput, device: DeviceContext) {
  const strength = isPasswordStrongEnough(input.password);
  if (!strength.ok) throw new AuthError("WEAK_PASSWORD", strength.reason!, 400);

  const existingUsername = await prisma.profile.findUnique({ where: { username: input.username } });
  if (existingUsername) throw new AuthError("USERNAME_TAKEN", "That username is already in use.", 409);

  if (input.method === "email") {
    const existing = await prisma.user.findUnique({ where: { email: input.email } });
    if (existing) throw new AuthError("EMAIL_IN_USE", "An account with this email already exists.", 409);
  } else {
    const existing = await prisma.user.findUnique({ where: { phone: input.phone } });
    if (existing) throw new AuthError("PHONE_IN_USE", "An account with this phone number already exists.", 409);
  }

  const passwordHash = await hashPassword(input.password);

  const user = await prisma.user.create({
    data: {
      email: input.method === "email" ? input.email : undefined,
      phone: input.method === "phone" ? input.phone : undefined,
      passwordHash,
      primaryProvider: input.method.toUpperCase() as AuthProvider,
      profile: {
        create: {
          username: input.username,
          fullName: input.fullName,
        },
      },
    },
    include: { profile: true },
  });

  // TODO(Phase 1 follow-up): send verification email/SMS via a queued job
  // rather than inline, so registration never blocks on a third-party API.
  logger.info({ userId: user.id }, "User registered");

  const session = await issueSession(user.id, user.role, device);
  return { user, ...session };
}

export async function login(identifier: string, password: string, device: DeviceContext) {
  const user = await prisma.user.findFirst({
    where: {
      OR: [{ email: identifier }, { phone: identifier }, { profile: { username: identifier } }],
    },
    include: { profile: true },
  });

  // Deliberately generic error for "not found" vs "wrong password" — never
  // reveal which part was wrong, that leaks account existence to attackers.
  if (!user || !user.passwordHash) {
    throw new AuthError("INVALID_CREDENTIALS", "Incorrect username/email/phone or password.", 401);
  }

  if (user.lockedUntil && user.lockedUntil > new Date()) {
    throw new AuthError(
      "ACCOUNT_LOCKED",
      `Too many failed attempts. Try again after ${user.lockedUntil.toISOString()}.`,
      423
    );
  }

  if (user.status !== "ACTIVE") {
    throw new AuthError("ACCOUNT_NOT_ACTIVE", "This account is suspended, banned, or deactivated.", 403);
  }

  const valid = await verifyPassword(user.passwordHash, password);
  if (!valid) {
    const failedCount = user.failedLoginCount + 1;
    const shouldLock = failedCount >= MAX_FAILED_LOGINS;
    await prisma.user.update({
      where: { id: user.id },
      data: {
        failedLoginCount: shouldLock ? 0 : failedCount,
        lockedUntil: shouldLock ? new Date(Date.now() + LOCKOUT_MINUTES * 60 * 1000) : undefined,
      },
    });
    throw new AuthError("INVALID_CREDENTIALS", "Incorrect username/email/phone or password.", 401);
  }

  // Successful login resets the failure counter.
  if (user.failedLoginCount > 0) {
    await prisma.user.update({ where: { id: user.id }, data: { failedLoginCount: 0, lockedUntil: null } });
  }

  // NOTE: MFA verification (for accounts with mfaEnabled) happens in the
  // controller before this function is trusted to issue a session — see
  // auth.controller.ts login handler.

  const session = await issueSession(user.id, user.role, device);
  return { user, ...session };
}

export async function refreshSession(refreshToken: string, device: DeviceContext) {
  const tokenHash = hashRefreshToken(refreshToken);
  const session = await prisma.session.findUnique({ where: { refreshTokenHash: tokenHash }, include: { user: true } });

  if (!session || session.revokedAt || session.expiresAt < new Date()) {
    throw new AuthError("SESSION_INVALID", "Session is invalid or has expired. Please log in again.", 401);
  }

  if (session.user.status !== "ACTIVE") {
    throw new AuthError("ACCOUNT_NOT_ACTIVE", "This account is not active.", 403);
  }

  // Rotate refresh token on every use (prevents replay if an old token leaks).
  const newRefreshToken = generateRefreshToken();
  await prisma.session.update({
    where: { id: session.id },
    data: {
      refreshTokenHash: hashRefreshToken(newRefreshToken),
      lastUsedAt: new Date(),
      expiresAt: new Date(Date.now() + refreshTtlMs()),
      ipAddress: device.ipAddress ?? session.ipAddress,
      userAgent: device.userAgent ?? session.userAgent,
    },
  });

  const accessToken = signAccessToken({ sub: session.userId, role: session.user.role as any, sid: session.id });
  return { accessToken, refreshToken: newRefreshToken };
}

export async function revokeSession(sessionId: string, userId: string) {
  // Scoped to userId so a user can only revoke their own sessions.
  await prisma.session.updateMany({
    where: { id: sessionId, userId, revokedAt: null },
    data: { revokedAt: new Date() },
  });
}

export async function revokeAllSessions(userId: string, exceptSessionId?: string) {
  await prisma.session.updateMany({
    where: { userId, revokedAt: null, ...(exceptSessionId ? { id: { not: exceptSessionId } } : {}) },
    data: { revokedAt: new Date() },
  });
}

export async function requestPasswordReset(identifier: string) {
  const user = await prisma.user.findFirst({
    where: { OR: [{ email: identifier }, { phone: identifier }] },
  });

  // Always behave as if the request succeeded, whether or not the account
  // exists — prevents attackers from using this endpoint to enumerate users.
  if (!user) {
    logger.info({ identifier }, "Password reset requested for unknown identifier (no-op)");
    return;
  }

  const rawToken = generateRefreshToken();
  await prisma.passwordResetToken.create({
    data: {
      userId: user.id,
      tokenHash: hashRefreshToken(rawToken),
      expiresAt: new Date(Date.now() + 60 * 60 * 1000), // 1 hour
    },
  });

  // TODO(Phase 1 follow-up): dispatch via email/SMS queue instead of logging.
  logger.info({ userId: user.id }, "Password reset token generated (deliver via email/SMS service)");
  return rawToken; // returned only so a queued job/controller can dispatch it — never returned to the HTTP client
}

export async function confirmPasswordReset(rawToken: string, newPassword: string) {
  const strength = isPasswordStrongEnough(newPassword);
  if (!strength.ok) throw new AuthError("WEAK_PASSWORD", strength.reason!, 400);

  const tokenHash = hashRefreshToken(rawToken);
  const resetRecord = await prisma.passwordResetToken.findUnique({ where: { tokenHash } });

  if (!resetRecord || resetRecord.usedAt || resetRecord.expiresAt < new Date()) {
    throw new AuthError("RESET_TOKEN_INVALID", "This password reset link is invalid or expired.", 400);
  }

  const passwordHash = await hashPassword(newPassword);

  await prisma.$transaction([
    prisma.user.update({ where: { id: resetRecord.userId }, data: { passwordHash } }),
    prisma.passwordResetToken.update({ where: { id: resetRecord.id }, data: { usedAt: new Date() } }),
    // Reset invalidates all existing sessions — if an attacker had a session
    // going, this locks them out the moment the real owner regains control.
    prisma.session.updateMany({
      where: { userId: resetRecord.userId, revokedAt: null },
      data: { revokedAt: new Date() },
    }),
  ]);
}
