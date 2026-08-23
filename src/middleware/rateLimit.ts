import rateLimit from "express-rate-limit";
import { RedisStore } from "rate-limit-redis";
import { redis } from "../lib/redis";
import { env } from "../config/env";

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
    // @ts-expect-error -- rate-limit-redis's types lag behind redis v4's API shape
    sendCommand: (...args: string[]) => redis.sendCommand(args),
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
    // @ts-expect-error -- see note above
    sendCommand: (...args: string[]) => redis.sendCommand(args),
    prefix: "rl:api:",
  }),
});
