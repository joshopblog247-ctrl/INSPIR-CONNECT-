import express, { NextFunction, Request, Response } from "express";
import helmet from "helmet";
import cors from "cors";
import cookieParser from "cookie-parser";
import pinoHttp from "pino-http";
import { env } from "./config/env";
import { logger } from "./lib/logger";
import { authRouter } from "./routes/auth.routes";
import { profileRouter } from "./routes/profile.routes";
import { apiRateLimiter } from "./middleware/rateLimit";

export function createApp() {
  const app = express();

  // Trust the first proxy hop (load balancer / reverse proxy in production)
  // so req.ip reflects the real client, not the proxy — needed for rate
  // limiting and audit logs to be meaningful.
  app.set("trust proxy", 1);

  app.use(helmet());
  app.use(
    cors({
      origin: env.corsOrigins,
      credentials: true,
    })
  );
  app.use(express.json({ limit: "1mb" }));
  app.use(cookieParser());
  app.use(pinoHttp({ logger, redact: ["req.headers.authorization", "req.headers.cookie"] }));
  app.use("/api", apiRateLimiter);

  app.get("/health", (_req, res) => {
    res.json({ status: "ok", service: "inspir-connect-backend", time: new Date().toISOString() });
  });

  app.use("/api/auth", authRouter);
  app.use("/api/profiles", profileRouter);

  // 404 handler
  app.use((req: Request, res: Response) => {
    res.status(404).json({ error: "NOT_FOUND", message: `No route for ${req.method} ${req.path}` });
  });

  // Centralized error handler — ensures no unhandled error ever leaks a
  // stack trace or internal detail to the client in production.
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  app.use((err: Error, req: Request, res: Response, _next: NextFunction) => {
    logger.error({ err, path: req.path }, "Unhandled error");
    res.status(500).json({
      error: "INTERNAL_ERROR",
      message: env.isProduction ? "Something went wrong." : err.message,
    });
  });

  return app;
}
