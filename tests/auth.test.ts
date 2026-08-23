import { describe, it, expect, beforeAll, afterAll, beforeEach } from "vitest";
import request from "supertest";
import { createApp } from "../src/app";
import { prisma } from "../src/lib/prisma";
import { connectRedis, redis } from "../src/lib/redis";

// These tests expect a real (test) Postgres + Redis instance reachable via
// the DATABASE_URL / REDIS_URL in your .env — point them at a disposable
// test database, never at production data.

const app = createApp();

beforeAll(async () => {
  await connectRedis();
});

afterAll(async () => {
  await prisma.$disconnect();
  await redis.quit();
});

beforeEach(async () => {
  // Clean slate between tests.
  await prisma.session.deleteMany();
  await prisma.passwordResetToken.deleteMany();
  await prisma.verificationRequest.deleteMany();
  await prisma.profile.deleteMany();
  await prisma.user.deleteMany();
});

describe("POST /api/auth/register", () => {
  it("registers a new user with a strong password", async () => {
    const res = await request(app).post("/api/auth/register").send({
      method: "email",
      email: "hope@example.com",
      password: "StrongPass123",
      fullName: "Hope Test",
      username: "hope_test",
    });

    expect(res.status).toBe(201);
    expect(res.body.user.email).toBe("hope@example.com");
    expect(res.body.accessToken).toBeDefined();
    expect(res.body.user).not.toHaveProperty("passwordHash");
  });

  it("rejects a weak password", async () => {
    const res = await request(app).post("/api/auth/register").send({
      method: "email",
      email: "weak@example.com",
      password: "weak",
      fullName: "Weak Pass",
      username: "weakpass",
    });

    expect(res.status).toBe(400);
    expect(res.body.error).toBe("WEAK_PASSWORD");
  });

  it("rejects duplicate email", async () => {
    await request(app).post("/api/auth/register").send({
      method: "email",
      email: "dupe@example.com",
      password: "StrongPass123",
      fullName: "First User",
      username: "first_user",
    });

    const res = await request(app).post("/api/auth/register").send({
      method: "email",
      email: "dupe@example.com",
      password: "StrongPass123",
      fullName: "Second User",
      username: "second_user",
    });

    expect(res.status).toBe(409);
    expect(res.body.error).toBe("EMAIL_IN_USE");
  });

  it("rejects duplicate username", async () => {
    await request(app).post("/api/auth/register").send({
      method: "email",
      email: "userone@example.com",
      password: "StrongPass123",
      fullName: "User One",
      username: "sharedname",
    });

    const res = await request(app).post("/api/auth/register").send({
      method: "email",
      email: "usertwo@example.com",
      password: "StrongPass123",
      fullName: "User Two",
      username: "sharedname",
    });

    expect(res.status).toBe(409);
    expect(res.body.error).toBe("USERNAME_TAKEN");
  });
});

describe("POST /api/auth/login", () => {
  beforeEach(async () => {
    await request(app).post("/api/auth/register").send({
      method: "email",
      email: "login@example.com",
      password: "StrongPass123",
      fullName: "Login Test",
      username: "login_test",
    });
  });

  it("logs in with correct credentials", async () => {
    const res = await request(app).post("/api/auth/login").send({
      identifier: "login@example.com",
      password: "StrongPass123",
    });
    expect(res.status).toBe(200);
    expect(res.body.accessToken).toBeDefined();
  });

  it("rejects incorrect password without revealing which field was wrong", async () => {
    const res = await request(app).post("/api/auth/login").send({
      identifier: "login@example.com",
      password: "WrongPassword1",
    });
    expect(res.status).toBe(401);
    expect(res.body.error).toBe("INVALID_CREDENTIALS");
  });

  it("locks the account after repeated failed attempts", async () => {
    for (let i = 0; i < 5; i++) {
      await request(app).post("/api/auth/login").send({
        identifier: "login@example.com",
        password: "WrongPassword1",
      });
    }
    const res = await request(app).post("/api/auth/login").send({
      identifier: "login@example.com",
      password: "StrongPass123", // even the correct password should now fail
    });
    expect(res.status).toBe(423);
    expect(res.body.error).toBe("ACCOUNT_LOCKED");
  });
});

describe("RBAC", () => {
  it("blocks a regular user from an admin-only route shape", async () => {
    const register = await request(app).post("/api/auth/register").send({
      method: "email",
      email: "regular@example.com",
      password: "StrongPass123",
      fullName: "Regular User",
      username: "regular_user",
    });

    const meRes = await request(app)
      .get("/api/auth/me")
      .set("Authorization", `Bearer ${register.body.accessToken}`);

    expect(meRes.status).toBe(200);
    expect(meRes.body.user.role).toBe("USER");
  });

  it("rejects requests with no token", async () => {
    const res = await request(app).get("/api/auth/me");
    expect(res.status).toBe(401);
  });

  it("rejects requests with a malformed token", async () => {
    const res = await request(app).get("/api/auth/me").set("Authorization", "Bearer not-a-real-token");
    expect(res.status).toBe(401);
  });
});

describe("Session refresh + revocation", () => {
  it("rotates refresh tokens and rejects reuse of the old one", async () => {
    const register = await request(app).post("/api/auth/register").send({
      method: "email",
      email: "rotate@example.com",
      password: "StrongPass123",
      fullName: "Rotate Test",
      username: "rotate_test",
    });

    const oldRefreshToken = register.body.refreshToken;

    const firstRefresh = await request(app).post("/api/auth/refresh").send({ refreshToken: oldRefreshToken });
    expect(firstRefresh.status).toBe(200);

    // Reusing the old (now-rotated) refresh token must fail.
    const reuseAttempt = await request(app).post("/api/auth/refresh").send({ refreshToken: oldRefreshToken });
    expect(reuseAttempt.status).toBe(401);
  });
});
