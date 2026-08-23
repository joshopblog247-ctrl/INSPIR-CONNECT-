import rateLimit from "express-rate-limit";
import { RedisStore } from "rate-limit-redis";
import { redis } from "../lib/redis";
import { env } from "../config/env";

// Ensures the Redis client is actually connected before any command runs.
// Without this, rate limiting can crash at startup if a request (or the
// store's own internal setup) arrives before the connection finishes.
async function sendCommand(...args: string[]) {
  if (!redis.isOpen) {
    await redis.connect();
  }
  return redis.sendCommand(args);
}

// Applied to auth endpoints (login, register, password reset) to blunt
// credential-stuffing and brute-force attacks. Keyed by IP; login attempts
// are additionally throttled per-account inside the auth service itself.
export const authRateLimiter = rateLimit({
  windowMs: env.authRateLimit.windowMs,
  max: env.authRateLimit.max,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "RATE_LIMITED", message: "Too many attempts. Please try again later." },
  store: new RedisStore({
    // @ts-ignore -- rate-limit-redis's types lag behind redis v4's actual API shape
    sendCommand,
    prefix: "rl:auth:",
  }),
});

// Looser general-purpose limiter for authenticated API traffic.
export const apiRateLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 120,
  standardHeaders: true,
  legacyHeaders: false,
  store: new RedisStore({
    // @ts-ignore -- see note above
    sendCommand,
    prefix: "rl:api:",
  }),
});
