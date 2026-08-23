import { Router } from "express";
import * as profileController from "../controllers/profile.controller";
import { requireAuth } from "../middleware/auth";

export const profileRouter = Router();

profileRouter.get("/:username", profileController.getByUsername); // public (subject to privacy check inside)
profileRouter.patch("/me", requireAuth, profileController.updateOwn);
profileRouter.post("/me/verification-request", requireAuth, profileController.requestVerification);
