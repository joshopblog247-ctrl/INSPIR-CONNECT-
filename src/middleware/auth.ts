import { Request, Response, NextFunction } from "express";
import { verifyAccessToken, AccessTokenPayload } from "../lib/jwt";
import { prisma } from "../lib/prisma";

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      auth?: AccessTokenPayload;
    }
  }
}

// Verifies the access token only — fast, no DB hit. Use for most routes.
export function requireAuth(req: Request, res: Response, next: NextFunction) {
  const header = req.headers.authorization;
  if (!header?.startsWith("Bearer ")) {
    return res.status(401).json({ error: "AUTH_REQUIRED", message: "Missing or invalid Authorization header." });
  }

  try {
    const payload = verifyAccessToken(header.slice(7));
    req.auth = payload;
    return next();
  } catch {
    return res.status(401).json({ error: "TOKEN_INVALID", message: "Access token is invalid or expired." });
  }
}

// Stronger check for sensitive account operations — confirms the user's
// current status against the database rather than trusting the token alone,
// since a token can still be "valid" for a few minutes after an account
// is suspended or banned.
export async function requireActiveAccount(req: Request, res: Response, next: NextFunction) {
  if (!req.auth) {
    return res.status(401).json({ error: "AUTH_REQUIRED" });
  }
  const user = await prisma.user.findUnique({ where: { id: req.auth.sub }, select: { status: true } });
  if (!user || user.status !== "ACTIVE") {
    return res.status(403).json({ error: "ACCOUNT_NOT_ACTIVE", message: "This account is not active." });
  }
  return next();
}

// RBAC: pass allowed roles, e.g. requireRole("PLATFORM_OWNER", "SUPER_ADMIN")
// CRITICAL: this check must run on the backend for every admin route — never
// rely on the frontend hiding a button as the actual access control.
export function requireRole(...allowedRoles: string[]) {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.auth) {
      return res.status(401).json({ error: "AUTH_REQUIRED" });
    }
    if (!allowedRoles.includes(req.auth.role)) {
      return res.status(403).json({ error: "FORBIDDEN", message: "You do not have permission to perform this action." });
    }
    return next();
  };
}
