import { OAuth2Client } from "google-auth-library";
import { env } from "../config/env";
import { prisma } from "../lib/prisma";
import { AuthError } from "./auth.service";

const client = env.GOOGLE_CLIENT_ID ? new OAuth2Client(env.GOOGLE_CLIENT_ID) : null;

// Verifies the ID token Google's SDK returns on the client (web or mobile),
// then finds-or-creates the corresponding user. Never trust a googleId or
// email sent directly from the client without this server-side verification.
export async function verifyGoogleIdToken(idToken: string) {
  if (!client) {
    throw new AuthError("GOOGLE_AUTH_DISABLED", "Google sign-in is not configured on this server.", 501);
  }

  const ticket = await client.verifyIdToken({ idToken, audience: env.GOOGLE_CLIENT_ID });
  const payload = ticket.getPayload();

  if (!payload?.sub || !payload.email) {
    throw new AuthError("GOOGLE_TOKEN_INVALID", "Could not verify Google identity token.", 401);
  }

  if (!payload.email_verified) {
    throw new AuthError("GOOGLE_EMAIL_UNVERIFIED", "Google account email is not verified.", 401);
  }

  return { googleId: payload.sub, email: payload.email, name: payload.name ?? "New User" };
}

export async function findOrCreateGoogleUser(googleId: string, email: string, name: string) {
  let user = await prisma.user.findUnique({ where: { googleId }, include: { profile: true } });
  if (user) return user;

  // Link by email if the account already exists via email/password signup.
  user = await prisma.user.findUnique({ where: { email }, include: { profile: true } });
  if (user) {
    return prisma.user.update({ where: { id: user.id }, data: { googleId }, include: { profile: true } });
  }

  // Generate a unique username from the email local-part.
  const base = email.split("@")[0].replace(/[^a-zA-Z0-9_.]/g, "").slice(0, 20) || "user";
  let username = base;
  let suffix = 0;
  while (await prisma.profile.findUnique({ where: { username } })) {
    suffix += 1;
    username = `${base}${suffix}`;
  }

  return prisma.user.create({
    data: {
      email,
      googleId,
      primaryProvider: "GOOGLE",
      emailVerifiedAt: new Date(),
      profile: { create: { username, fullName: name } },
    },
    include: { profile: true },
  });
}
