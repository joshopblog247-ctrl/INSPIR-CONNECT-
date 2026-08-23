import { Request, Response } from "express";
import { updateProfileSchema, verificationRequestSchema } from "../utils/validation";
import * as profileService from "../services/profile.service";
import { AuthError } from "../services/auth.service";
import { logger } from "../lib/logger";

export async function getByUsername(req: Request, res: Response) {
  try {
    const profile = await profileService.getProfileByUsername(req.params.username, req.auth?.sub);
    return res.json({ profile });
  } catch (err) {
    if (err instanceof AuthError) return res.status(err.status).json({ error: err.code, message: err.message });
    logger.error({ err }, "Get profile failed");
    return res.status(500).json({ error: "INTERNAL_ERROR" });
  }
}

export async function updateOwn(req: Request, res: Response) {
  if (!req.auth) return res.status(401).json({ error: "AUTH_REQUIRED" });
  const parsed = updateProfileSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: "VALIDATION_ERROR", details: parsed.error.flatten() });
  }
  try {
    const profile = await profileService.updateOwnProfile(req.auth.sub, parsed.data);
    return res.json({ profile });
  } catch (err) {
    logger.error({ err }, "Update profile failed");
    return res.status(500).json({ error: "INTERNAL_ERROR" });
  }
}

export async function requestVerification(req: Request, res: Response) {
  if (!req.auth) return res.status(401).json({ error: "AUTH_REQUIRED" });
  const parsed = verificationRequestSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: "VALIDATION_ERROR", details: parsed.error.flatten() });
  }
  try {
    const request = await profileService.submitVerificationRequest(req.auth.sub, parsed.data);
    return res.status(201).json({ request });
  } catch (err) {
    if (err instanceof AuthError) return res.status(err.status).json({ error: err.code, message: err.message });
    logger.error({ err }, "Verification request failed");
    return res.status(500).json({ error: "INTERNAL_ERROR" });
  }
}
