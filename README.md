# INSPIR CONNECT — Backend (Phase 1: Auth + Profiles)

Real, runnable code — not a mockup. This is the foundation everything else
(feed, messaging, groups, admin) will be built on top of.

## What's actually in here

- **Registration** — email or phone, argon2id password hashing, strong-password
  enforcement, duplicate email/phone/username checks.
- **Login** — generic error messages (never reveal whether the email or the
  password was wrong), account lockout after 5 failed attempts (15 min),
  optional MFA (TOTP) support.
- **Google Sign-In** — server-side ID token verification, account
  find-or-create, account linking by email.
- **Sessions** — short-lived JWT access tokens (15 min) + long-lived opaque
  refresh tokens (30 days), rotated on every refresh, hashed at rest in the
  database (a DB leak alone can't forge a working session).
- **Password reset** — token-based, anti-enumeration (same response whether
  or not the account exists), invalidates all sessions on successful reset.
- **Session management** — list active sessions/devices, revoke one, revoke
  all ("log out everywhere").
- **RBAC scaffolding** — 8 roles from `PLATFORM_OWNER` down to `USER`,
  enforced in backend middleware (`requireRole(...)`), never trusted from
  the frontend.
- **Profiles** — username, bio, location, occupation, interests, privacy
  levels, verification-request submission flow.
- **Rate limiting** — Redis-backed, applied to all auth endpoints.
- **Audit log table** — ready for admin actions in Phase 8 (append-only by
  convention — application code never updates/deletes rows in it).
- **Tests** — registration, login, lockout, RBAC, refresh-token rotation
  and reuse-rejection, using a real test database (not mocks) via Supertest.

## What's deliberately NOT in here yet

This is Phase 1 only. Feed, messaging, groups, video, marketplace, and the
admin dashboard come in later phases per the roadmap — building them all at
once was the trap we're avoiding. Also not yet wired up:

- Actual email/SMS delivery (verification, password reset) — the service
  functions generate tokens and log them; wiring a provider (e.g. Resend,
  Twilio) is a small, isolated follow-up.
- MFA *enrollment* endpoints (the *verification* check at login exists;
  the "scan this QR code to turn MFA on" endpoint is next).
- The Platform Owner dashboard UI — the account and RBAC exist; the UI is
  Phase 8.

## Setup (GitHub Codespaces or local)

You need Node.js 20+, PostgreSQL, and Redis. In Codespaces, the easiest path
is to add Postgres + Redis as dev containers, or use free-tier hosted
instances (e.g. Neon for Postgres, Upstash for Redis) — either works, since
the app only needs `DATABASE_URL` and `REDIS_URL`.

```bash
# 1. Install dependencies
npm install

# 2. Copy env template and fill in real values
cp .env.example .env
# Edit .env: set DATABASE_URL, REDIS_URL, and generate secrets with:
openssl rand -base64 64   # run twice, once for each JWT secret

# 3. Create the database schema
npx prisma migrate dev --name init

# 4. Bootstrap the Platform Owner account (one-time)
#    Set OWNER_BOOTSTRAP_EMAIL / OWNER_BOOTSTRAP_PASSWORD in .env first
npx tsx prisma/seed.ts

# 5. Start the dev server
npm run dev
```

Server runs on `http://localhost:4000` (or your Codespaces forwarded URL).
Check it's alive: `curl http://localhost:4000/health`

## Quick manual test

```bash
# Register
curl -X POST http://localhost:4000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"method":"email","email":"you@example.com","password":"StrongPass123","fullName":"Hope","username":"hope"}'

# Login
curl -X POST http://localhost:4000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"identifier":"you@example.com","password":"StrongPass123"}'

# Use the returned accessToken:
curl http://localhost:4000/api/auth/me \
  -H "Authorization: Bearer <accessToken>"
```

## Running tests

Point `.env` at a **disposable test database** (never production), then:

```bash
npm test
```

## Connecting your Expo app

From React Native, store `accessToken` in memory (React state/context) and
`refreshToken` in `expo-secure-store` (never AsyncStorage — it's unencrypted).
On a 401 from the API, call `/api/auth/refresh` with the stored refresh
token, update both tokens, and retry the original request once.

## A note on scale

This is sized correctly for "small community, real users" — not
over-engineered for millions of users you don't have yet. Postgres,
one API process, and Redis for rate-limiting will comfortably handle
thousands of users. The horizontal-scaling groundwork (stateless JWT auth,
Redis-backed rate limiting instead of in-memory, no server-side session
affinity) is already in place so you can add more API instances behind a
load balancer later without re-architecting.
