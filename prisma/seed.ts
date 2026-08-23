// One-time bootstrap: creates the Platform Owner account from env vars.
// Run: npx tsx prisma/seed.ts
// IMPORTANT: change OWNER_BOOTSTRAP_PASSWORD immediately after first login,
// and remove/rotate it from .env once the owner has logged in and set MFA.

import "dotenv/config";
import { PrismaClient } from "@prisma/client";
import argon2 from "argon2";

const prisma = new PrismaClient();

async function main() {
  const email = process.env.OWNER_BOOTSTRAP_EMAIL;
  const password = process.env.OWNER_BOOTSTRAP_PASSWORD;

  if (!email || !password) {
    throw new Error("OWNER_BOOTSTRAP_EMAIL and OWNER_BOOTSTRAP_PASSWORD must be set in .env");
  }

  const existingOwner = await prisma.user.findFirst({ where: { role: "PLATFORM_OWNER" } });
  if (existingOwner) {
    console.log("A Platform Owner account already exists. Skipping seed.");
    return;
  }

  const passwordHash = await argon2.hash(password, { type: argon2.argon2id, memoryCost: 19456, timeCost: 2, parallelism: 1 });

  const owner = await prisma.user.create({
    data: {
      email,
      passwordHash,
      role: "PLATFORM_OWNER",
      status: "ACTIVE",
      emailVerifiedAt: new Date(),
      profile: {
        create: {
          username: "platform_owner",
          fullName: "INSPIR CONNECT Platform Owner",
          privacyLevel: "private",
        },
      },
    },
  });

  console.log(`✅ Platform Owner created: ${owner.email} (id: ${owner.id})`);
  console.log("⚠️  Log in now, enable MFA, and change this password immediately.");
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(() => prisma.$disconnect());
