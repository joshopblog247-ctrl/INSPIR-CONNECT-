import { PrismaClient } from "@prisma/client";
import { env } from "../config/env";

// Prevent multiple PrismaClient instances in dev (hot reload) exhausting DB connections.
declare global {
  // eslint-disable-next-line no-var
  var __prisma__: PrismaClient | undefined;
}

export const prisma =
  global.__prisma__ ??
  new PrismaClient({
    log: env.isProduction ? ["error", "warn"] : ["error", "warn", "query"],
  });

if (!env.isProduction) {
  global.__prisma__ = prisma;
}
