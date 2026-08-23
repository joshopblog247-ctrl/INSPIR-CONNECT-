import rateLimit from "express-rate-limit";
import { RedisStore } from "rate-limit-redis";
import { redis } from "../lib/redis";
import { env } from "../config/env";

/**
 * Execute Redis commands safely.
 * Connects the Redis client before sending the command.
 */
async function sendCommand(
  ...args: string[]
): Promise<unknown> {
  if (!redis.isOpen) {
    await redis.connect();
  }

  return redis.sendCommand(args);
}

/**
 * Rate limiter for authentication endpoints:
 * - Login
 * - Registration
 * - Password reset
 *
 * Helps protect against brute-force and credential-stuffing attacks.
 * Requests are primarily limited by IP address.
 */
export const authRateLimiter = rateLimit({
  windowMs: env.authRateLimit.windowMs,
  max: env.authRateLimit.max,

  standardHeaders: true,
  legacyHeaders: false,

  message: {
    error: "RATE_LIMITED",
    message: "Too many attempts. Please try again later.",
  },

  store: new RedisStore({
    sendCommand,
    prefix: "rl:auth:",
  }),
});

/**
 * General API rate limiter for authenticated users.
 *
 * Limit:
 * 120 requests per minute per client/IP.
 */
export const apiRateLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 120,

  standardHeaders: true,
  legacyHeaders: false,

  message: {
    error: "RATE_LIMITED",
    message: "Too many requests. Please try again later.",
  },

  store: new RedisStore({
    sendCommand,
    prefix: "rl:api:",
  }),
});
