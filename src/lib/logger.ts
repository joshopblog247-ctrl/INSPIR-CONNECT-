import pino from "pino";
import { env } from "../config/env";

export const logger = pino({
  level: env.isProduction ? "info" : "debug",
  transport: env.isProduction
    ? undefined
    : {
        target: "pino-pretty",
        options: { colorize: true, translateTime: "HH:MM:ss", ignore: "pid,hostname" },
      },
  // Never log sensitive fields even if accidentally passed in.
  redact: ["password", "passwordHash", "*.password", "*.token", "*.refreshToken", "*.mfaSecret"],
});
