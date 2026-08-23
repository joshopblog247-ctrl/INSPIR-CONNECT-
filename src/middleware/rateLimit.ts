import rateLimit from "express-rate-limit";
import { RedisStore } from "rate-limit-redis";
import { redis, connectRedis } from "../lib/redis";
import { env } from "../config/env";

// Reconnects if the client has dropped (e.g. free-tier idle disconnects)
// before forwarding the command, using the shared safe-reconnect helper.
async function sendCommand(...args: string[]) {
  if (!redis.isOpen) {
    await connectRedis();
  }
  return redis.sendCommand(args);
}

export const authRateLimiter = rateLimit({
  windowMs: env.authRateLimit.windowMs,
  max: env.authRateLimit.max,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "RATE_LIMITED", message: "Too many attempts. Please try again later." },
  store: new RedisStore({
    sendCommand,
    prefix: "rl:auth:",
  } as any),
});

export const apiRateLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 120,
  standardHeaders: true,
  legacyHeaders: false,
  store: new RedisStore({
    sendCommand,
    prefix: "rl:api:",
  } as any),
});
