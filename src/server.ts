import { createApp } from "./app";
import { env } from "./config/env";
import { connectRedis, redis } from "./lib/redis";
import { prisma } from "./lib/prisma";
import { logger } from "./lib/logger";

async function main() {
  await connectRedis();

  const app = createApp();
  const server = app.listen(env.PORT, () => {
    logger.info(`INSPIR CONNECT backend listening on port ${env.PORT} [${env.NODE_ENV}]`);
  });

  // Graceful shutdown — finish in-flight requests, then close DB/Redis
  // connections cleanly. Matters in production behind an orchestrator
  // (e.g. Kubernetes) that sends SIGTERM before killing the process.
  const shutdown = async (signal: string) => {
    logger.info(`Received ${signal}, shutting down gracefully...`);
    server.close(async () => {
      await prisma.$disconnect();
      await redis.quit();
      logger.info("Shutdown complete.");
      process.exit(0);
    });
    // Force-exit if graceful shutdown hangs.
    setTimeout(() => process.exit(1), 10_000).unref();
  };

  process.on("SIGTERM", () => shutdown("SIGTERM"));
  process.on("SIGINT", () => shutdown("SIGINT"));
}

main().catch((err) => {
  logger.error({ err }, "Fatal startup error");
  process.exit(1);
});
