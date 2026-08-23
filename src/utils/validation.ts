import { z } from "zod";

// E.164-ish phone check: + followed by 8-15 digits.
const phoneRegex = /^\+[1-9]\d{7,14}$/;

export const registerSchema = z
  .object({
    method: z.enum(["email", "phone"]),
    email: z.string().email().optional(),
    phone: z.string().regex(phoneRegex, "Phone must be in E.164 format, e.g. +2348012345678").optional(),
    password: z.string().min(10),
    fullName: z.string().min(2).max(100),
    username: z
      .string()
      .min(3)
      .max(30)
      .regex(/^[a-zA-Z0-9_.]+$/, "Username can only contain letters, numbers, underscores, and dots."),
  })
  .refine((data) => (data.method === "email" ? !!data.email : !!data.phone), {
    message: "Email is required when method is 'email', phone is required when method is 'phone'.",
  });

export const loginSchema = z.object({
  identifier: z.string().min(3), // email, phone, or username
  password: z.string().min(1),
  mfaCode: z.string().length(6).optional(),
});

export const googleAuthSchema = z.object({
  idToken: z.string().min(20),
});

export const passwordResetRequestSchema = z.object({
  identifier: z.string().min(3),
});

export const passwordResetConfirmSchema = z.object({
  token: z.string().min(10),
  newPassword: z.string().min(10),
});

export const refreshTokenSchema = z.object({
  refreshToken: z.string().min(20),
});

export const updateProfileSchema = z.object({
  fullName: z.string().min(2).max(100).optional(),
  bio: z.string().max(500).optional(),
  location: z.string().max(100).optional(),
  occupation: z.string().max(100).optional(),
  interests: z.array(z.string().max(30)).max(20).optional(),
  privacyLevel: z.enum(["public", "followers", "private"]).optional(),
});

export const verificationRequestSchema = z.object({
  reason: z.string().min(20).max(1000),
  category: z.enum(["community", "business", "creator", "organization"]),
  evidenceUrl: z.string().url().optional(),
});
