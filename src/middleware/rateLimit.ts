import rateLimit from "express-rate-limit";
import { RedisStore } from "rate-limit-redis";
import { redis } from "../lib/redis";
import { env } from "../config/env";
import type { RedisReply } from "rate-limit-redis";

async function sendCommand(...args: string[]): Promise<RedisReply> {
  if (!redis.isOpen) {
    await redis.connect();
  }

  return redis.sendCommand(args) as Promise<RedisReply>;
}

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
