import { createClient } from "redis";
import { env } from "../config/env";
import { logger } from "./logger";

export const redis = createClient({ url: env.REDIS_URL });

redis.on("error", (err) => logger.error({ err }, "Redis client error"));

// Guards against multiple simultaneous connect attempts (which throws
// "Socket already opened"). Any caller can safely call this any number
// of times; only one real connection attempt happens at once.
let connectingPromise: Promise<unknown> | null = null;

export async function connectRedis() {
  if (redis.isOpen) return;
  if (!connectingPromise) {
    connectingPromise = redis.connect().finally(() => {
      connectingPromise = null;
    });
  }
  return connectingPromise;
}
