import { Router } from "express";
import * as authController from "../controllers/auth.controller";
import { requireAuth } from "../middleware/auth";
import { authRateLimiter } from "../middleware/rateLimit";

export const authRouter = Router();

// Public, but rate-limited to blunt brute-force / credential stuffing.
authRouter.post("/register", authRateLimiter, authController.register);
authRouter.post("/login", authRateLimiter, authController.login);
authRouter.post("/google", authRateLimiter, authController.googleAuth);
authRouter.post("/refresh", authRateLimiter, authController.refresh);
authRouter.post("/password-reset/request", authRateLimiter, authController.requestPasswordReset);
authRouter.post("/password-reset/confirm", authRateLimiter, authController.confirmPasswordReset);

// Requires a valid access token.
authRouter.post("/logout", requireAuth, authController.logout);
authRouter.post("/logout-all", requireAuth, authController.logoutAllDevices);
authRouter.get("/me", requireAuth, authController.me);
authRouter.get("/sessions", requireAuth, authController.listSessions);
authRouter.delete("/sessions/:sessionId", requireAuth, authController.revokeSpecificSession);
