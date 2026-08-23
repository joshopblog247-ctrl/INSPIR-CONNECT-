import { Request, Response } from "express";
import {
  registerSchema,
  loginSchema,
  googleAuthSchema,
  passwordResetRequestSchema,
  passwordResetConfirmSchema,
  refreshTokenSchema,
} from "../utils/validation";
import * as authService from "../services/auth.service";
import * as googleAuthService from "../services/google-auth.service";
import { prisma } from "../lib/prisma";
import { logger } from "../lib/logger";

function deviceContext(req: Request) {
  return {
    ipAddress: req.ip,
    userAgent: req.headers["user-agent"],
    deviceLabel: (req.headers["x-device-label"] as string) || undefined,
  };
}

// Refresh tokens are set as httpOnly cookies for web clients (XSS-resistant)
// AND returned in the JSON body for mobile clients (which store them in
// secure device storage — Expo SecureStore — since RN has no cookie jar
// concept the same way browsers do).
function setRefreshCookie(res: Response, token: string) {
  res.cookie("refreshToken", token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    path: "/api/auth",
    maxAge: 30 * 24 * 60 * 60 * 1000,
  });
}

function toPublicUser(user: any) {
  return {
    id: user.id,
    email: user.email,
    phone: user.phone,
    role: user.role,
    status: user.status,
    mfaEnabled: user.mfaEnabled,
    profile: user.profile
      ? {
          username: user.profile.username,
          fullName: user.profile.fullName,
          avatarUrl: user.profile.avatarUrl,
          isVerified: user.profile.isVerified,
        }
      : null,
  };
}

export async function register(req: Request, res: Response) {
  const parsed = registerSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: "VALIDATION_ERROR", details: parsed.error.flatten() });
  }

  try {
    const { user, accessToken, refreshToken } = await authService.register(parsed.data, deviceContext(req));
    setRefreshCookie(res, refreshToken);
    return res.status(201).json({ user: toPublicUser(user), accessToken, refreshToken });
  } catch (err) {
    if (err instanceof authService.AuthError) {
      return res.status(err.status).json({ error: err.code, message: err.message });
    }
    logger.error({ err }, "Registration failed");
    return res.status(500).json({ error: "INTERNAL_ERROR" });
  }
}

export async function login(req: Request, res: Response) {
  const parsed = loginSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: "VALIDATION_ERROR", details: parsed.error.flatten() });
  }

  try {
    // Look up MFA status before issuing a session, so an MFA-enabled account
    // can never receive tokens on password alone.
    const candidate = await prisma.user.findFirst({
      where: {
        OR: [
          { email: parsed.data.identifier },
          { phone: parsed.data.identifier },
          { profile: { username: parsed.data.identifier } },
        ],
      },
      select: { mfaEnabled: true, mfaSecret: true },
    });

    if (candidate?.mfaEnabled) {
      if (!parsed.data.mfaCode) {
        return res.status(401).json({ error: "MFA_REQUIRED", message: "Enter your 6-digit authenticator code." });
      }
      const { authenticator } = await import("otplib");
      const validCode = candidate.mfaSecret && authenticator.check(parsed.data.mfaCode, candidate.mfaSecret);
      if (!validCode) {
        return res.status(401).json({ error: "MFA_INVALID", message: "Invalid authentication code." });
      }
    }

    const { user, accessToken, refreshToken } = await authService.login(
      parsed.data.identifier,
      parsed.data.password,
      deviceContext(req)
    );
    setRefreshCookie(res, refreshToken);
    return res.json({ user: toPublicUser(user), accessToken, refreshToken });
  } catch (err) {
    if (err instanceof authService.AuthError) {
      return res.status(err.status).json({ error: err.code, message: err.message });
    }
    logger.error({ err }, "Login failed");
    return res.status(500).json({ error: "INTERNAL_ERROR" });
  }
}

export async function googleAuth(req: Request, res: Response) {
  const parsed = googleAuthSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: "VALIDATION_ERROR", details: parsed.error.flatten() });
  }

  try {
    const { googleId, email, name } = await googleAuthService.verifyGoogleIdToken(parsed.data.idToken);
    const user = await googleAuthService.findOrCreateGoogleUser(googleId, email, name);
    const { accessToken, refreshToken } = await authService.issueSession(user.id, user.role, deviceContext(req));
    setRefreshCookie(res, refreshToken);
    return res.json({ user: toPublicUser(user), accessToken, refreshToken });
  } catch (err) {
    if (err instanceof authService.AuthError) {
      return res.status(err.status).json({ error: err.code, message: err.message });
    }
    logger.error({ err }, "Google auth failed");
    return res.status(500).json({ error: "INTERNAL_ERROR" });
  }
}

export async function refresh(req: Request, res: Response) {
  const tokenFromCookie = req.cookies?.refreshToken;
  const parsed = refreshTokenSchema.safeParse({ refreshToken: tokenFromCookie ?? req.body.refreshToken });
  if (!parsed.success) {
    return res.status(400).json({ error: "VALIDATION_ERROR", details: parsed.error.flatten() });
  }

  try {
    const { accessToken, refreshToken } = await authService.refreshSession(parsed.data.refreshToken, deviceContext(req));
    setRefreshCookie(res, refreshToken);
    return res.json({ accessToken, refreshToken });
  } catch (err) {
    if (err instanceof authService.AuthError) {
      return res.status(err.status).json({ error: err.code, message: err.message });
    }
    logger.error({ err }, "Refresh failed");
    return res.status(500).json({ error: "INTERNAL_ERROR" });
  }
}

export async function logout(req: Request, res: Response) {
  if (req.auth) {
    await authService.revokeSession(req.auth.sid, req.auth.sub);
  }
  res.clearCookie("refreshToken", { path: "/api/auth" });
  return res.status(204).send();
}

export async function logoutAllDevices(req: Request, res: Response) {
  if (!req.auth) return res.status(401).json({ error: "AUTH_REQUIRED" });
  await authService.revokeAllSessions(req.auth.sub);
  res.clearCookie("refreshToken", { path: "/api/auth" });
  return res.status(204).send();
}

export async function requestPasswordReset(req: Request, res: Response) {
  const parsed = passwordResetRequestSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: "VALIDATION_ERROR", details: parsed.error.flatten() });
  }
  await authService.requestPasswordReset(parsed.data.identifier);
  // Always 200, regardless of whether the account exists (anti-enumeration).
  return res.json({ message: "If an account exists, a reset link has been sent." });
}

export async function confirmPasswordReset(req: Request, res: Response) {
  const parsed = passwordResetConfirmSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: "VALIDATION_ERROR", details: parsed.error.flatten() });
  }
  try {
    await authService.confirmPasswordReset(parsed.data.token, parsed.data.newPassword);
    return res.json({ message: "Password updated. Please log in again." });
  } catch (err) {
    if (err instanceof authService.AuthError) {
      return res.status(err.status).json({ error: err.code, message: err.message });
    }
    logger.error({ err }, "Password reset confirmation failed");
    return res.status(500).json({ error: "INTERNAL_ERROR" });
  }
}

export async function me(req: Request, res: Response) {
  if (!req.auth) return res.status(401).json({ error: "AUTH_REQUIRED" });
  const user = await prisma.user.findUnique({ where: { id: req.auth.sub }, include: { profile: true } });
  if (!user) return res.status(404).json({ error: "USER_NOT_FOUND" });
  return res.json({ user: toPublicUser(user) });
}

export async function listSessions(req: Request, res: Response) {
  if (!req.auth) return res.status(401).json({ error: "AUTH_REQUIRED" });
  const sessions = await prisma.session.findMany({
    where: { userId: req.auth.sub, revokedAt: null },
    select: { id: true, deviceLabel: true, ipAddress: true, createdAt: true, lastUsedAt: true, expiresAt: true },
    orderBy: { lastUsedAt: "desc" },
  });
  return res.json({ sessions, currentSessionId: req.auth.sid });
}

export async function revokeSpecificSession(req: Request, res: Response) {
  if (!req.auth) return res.status(401).json({ error: "AUTH_REQUIRED" });
  await authService.revokeSession(req.params.sessionId, req.auth.sub);
  return res.status(204).send();
}
