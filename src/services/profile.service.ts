import { prisma } from "../lib/prisma";
import { AuthError } from "./auth.service";

export async function getProfileByUsername(username: string, viewerId?: string) {
  const profile = await prisma.profile.findUnique({
    where: { username },
    include: { user: { select: { id: true, status: true, createdAt: true } } },
  });

  if (!profile || profile.user.status !== "ACTIVE") {
    throw new AuthError("PROFILE_NOT_FOUND", "Profile not found.", 404);
  }

  // Private profile enforcement — full follow-graph check is a Phase 2
  // concern (once the Follow model exists); for now, private profiles are
  // only visible to their owner, everything else is enforced at that layer.
  if (profile.privacyLevel === "private" && profile.userId !== viewerId) {
    return {
      username: profile.username,
      fullName: profile.fullName,
      avatarUrl: profile.avatarUrl,
      isVerified: profile.isVerified,
      isPrivate: true,
    };
  }

  return profile;
}

export async function updateOwnProfile(userId: string, updates: Record<string, unknown>) {
  return prisma.profile.update({ where: { userId }, data: updates });
}

export async function submitVerificationRequest(
  userId: string,
  data: { reason: string; category: string; evidenceUrl?: string }
) {
  const existing = await prisma.verificationRequest.findFirst({
    where: { userId, status: "PENDING" },
  });
  if (existing) {
    throw new AuthError("VERIFICATION_ALREADY_PENDING", "You already have a pending verification request.", 409);
  }

  return prisma.verificationRequest.create({
    data: { userId, reason: data.reason, category: data.category, evidenceUrl: data.evidenceUrl },
  });
}
