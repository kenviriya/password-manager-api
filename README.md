# Password Manager API

Backend API for a password manager MVP built with Node.js + TypeScript using NestJS (on top of Express), Drizzle ORM, PostgreSQL, and Redis.

## Backend Engineering Focus (Node.js / Express.js / NestJS)

This project is intentionally structured to demonstrate practical backend engineering skills across the Node.js ecosystem:

- `Node.js backend fundamentals`
  - async I/O with PostgreSQL and Redis
  - environment-based configuration
  - HTTP server concerns (CORS, cookies, sessions, error handling, graceful shutdown)
- `Express.js concepts` (applied through NestJS)
  - request/response lifecycle
  - middleware-driven auth/session parsing
  - route-level protection and rate limiting
  - consistent response/error formatting
- `NestJS architecture`
  - modular design (`AuthModule`, `VaultModule`, shared infrastructure modules)
  - dependency injection for services/providers
  - controllers/services separation
  - guards, interceptors, filters, decorators, and pipes

NestJS is the framework used in this repo, and it runs on the Express platform adapter (`@nestjs/platform-express`). That means the code demonstrates both higher-level NestJS patterns and the underlying Express-style HTTP flow they build on.

## Implemented Features

- Local auth (`email + password`) with `argon2id`
- Google OAuth login
- Session-based authentication with Redis (`sid` cookie)
- Vault item CRUD (server-managed encryption with AES-256-GCM)
- Consistent API response envelope (success/error)
- Global Redis-backed rate limiting with route-specific policies
- Zod request validation
- Unit tests for auth and vault controllers/services

## Stack

- Node.js (runtime)
- TypeScript
- NestJS
- Express (via NestJS platform adapter)
- Drizzle ORM
- PostgreSQL
- Redis
- Zod
- Argon2
- ioredis

## Project Structure (High-level)

- `src/modules/auth`
  - local auth, Google OAuth, sessions, route protection
- `src/modules/vault`
  - encrypted vault CRUD
- `src/common/database`
  - Drizzle provider + schema
- `src/common/redis`
  - Redis client provider/module
- `src/common/rate-limit`
  - global Redis rate-limit guard + decorators
- `src/common/http`, `src/common/filters`, `src/common/interceptors`
  - response envelope and exception formatting

## Express.js to NestJS Mapping (What This Repo Demonstrates)

- `Express routes/controllers` -> NestJS controllers (`src/modules/auth/auth.controller.ts`, `src/modules/vault/vault.controller.ts`)
- `Express middleware` -> NestJS middleware (`src/modules/auth/middleware/auth.middleware.ts`)
- `Express request guards/policies` -> NestJS guards + decorators (`src/modules/auth/guards`, `src/common/rate-limit`)
- `Express error middleware` -> NestJS exception filters (`src/common/filters/api-exception.filter.ts`)
- `Express response shaping middleware` -> NestJS interceptors (`src/common/interceptors/api-response.interceptor.ts`)
- `Manual validation middleware` -> NestJS pipes with Zod (`src/common/pipes/zod-validation.pipe.ts`)

This is useful if you're evaluating the project as an `Express.js backend` as well as a `NestJS backend`: the same HTTP concerns are present, but organized with NestJS modules and dependency injection.

## Local Setup

### 1. Install dependencies

```bash
npm install
```

### 2. Start PostgreSQL and Redis (Docker)

```bash
docker compose up -d
```

`docker-compose.yml` starts:
- PostgreSQL (`localhost:5432`)
- Redis (`localhost:6379`)

### 3. Create `.env`

Example:

```env
PORT=3000
NODE_ENV=development

DATABASE_URL=postgresql://password-manager:password-manager@localhost:5432/password_manager_dev
REDIS_URL=redis://localhost:6379

AUTH_SESSION_TTL_SECONDS=604800

# 32-byte key (recommended in production). Supported: 64-char hex, base64, or hex:/base64: prefix.
# VAULT_ENCRYPTION_KEY=hex:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef

# Google OAuth (required for /auth/google)
# GOOGLE_CLIENT_ID=...
# GOOGLE_CLIENT_SECRET=...
# GOOGLE_OAUTH_REDIRECT_URI=http://localhost:3000/auth/google/callback
# Optional frontend redirects after callback (recommended for frontend app UX)
# GOOGLE_OAUTH_SUCCESS_REDIRECT_URL=http://localhost:3000/auth/callback/success
# GOOGLE_OAUTH_ERROR_REDIRECT_URL=http://localhost:3000/auth/callback/error

# Rate limit (optional)
# RATE_LIMIT_DEFAULT_LIMIT=120
# RATE_LIMIT_DEFAULT_WINDOW_SECONDS=60
# RATE_LIMIT_AUTH_LIMIT=10
# RATE_LIMIT_AUTH_WINDOW_SECONDS=60
```

Notes:
- If `VAULT_ENCRYPTION_KEY` is missing in development, the app falls back to a key derived from `DATABASE_URL` (development fallback only).
- In production, set `VAULT_ENCRYPTION_KEY` explicitly.

### 4. Push schema to database (Drizzle)

```bash
npx drizzle-kit push
```

If you see `role "password-manager" does not exist`, your Postgres volume may have been initialized with different credentials. For a fresh local reset:

```bash
docker compose down -v
docker compose up -d
```

### 5. Run the API

```bash
npm run start:dev
```

Default local URL:
- `http://localhost:3000`

Local frontend note:
- CORS is currently enabled for `http://localhost:3000` with `credentials: true` (for session cookie auth).

### 6. Seed a local test user (optional)

```bash
npm run seed:user
```

Seeded credentials:
- `email`: `user@example.com`
- `password`: `password`

The seed is idempotent:
- creates the user if missing
- updates the password hash if the user already exists
- ensures local auth records exist (`users`, `user_credentials`, `oauth_accounts`)

### 7. Seed vault items for the test user (optional)

```bash
npm run seed:vault
```

This seeds `5` encrypted vault items for `user@example.com`:
- `Seed • GitHub`
- `Seed • Gmail`
- `Seed • AWS Console`
- `Seed • Netflix`
- `Seed • Banking`

The seed is idempotent for these items:
- removes previous seed items (same titles) for the seeded user
- inserts fresh encrypted rows

Convenience command (user + vault items):

```bash
npm run seed:dev
```

## Scripts

- `npm run build`
- `npm run start`
- `npm run start:dev`
- `npm run start:prod`
- `npm run test`
- `npm run test:cov`
- `npm run seed:user`
- `npm run seed:vault`
- `npm run seed:dev`

## Authentication Model

- Session-based auth (not JWT)
- Session cookie name: `sid`
- Session data stored in Redis
- Cookie flags:
  - `httpOnly: true`
  - `sameSite: "lax"`
  - `secure: true` in production

Frontend clients must send credentials:

```ts
fetch('/auth/me', { credentials: 'include' });
```

## API Response Format

### Success

```json
{
  "success": true,
  "message": "Vault item fetched",
  "data": {
    "item": {}
  },
  "meta": {
    "timestamp": "2026-02-22T12:00:00.000Z",
    "path": "/vault/items/..."
  }
}
```

### Error

```json
{
  "success": false,
  "message": "Validation failed",
  "error": {
    "code": "VALIDATION_ERROR",
    "statusCode": 400,
    "details": []
  },
  "meta": {
    "timestamp": "2026-02-22T12:00:00.000Z",
    "path": "/auth/login"
  }
}
```

## API Overview

### Auth (`/auth`)

- `POST /auth/register`
- `POST /auth/login`
- `GET /auth/google`
- `GET /auth/google/callback`
- `GET /auth/me`
- `PATCH /auth/password`
- `POST /auth/logout`

### Vault (`/vault/items`)

- `POST /vault/items`
- `GET /vault/items`
- `GET /vault/items/:id`
- `PATCH /vault/items/:id`
- `DELETE /vault/items/:id`

## Google OAuth Flow (Current Behavior)

1. Client navigates to `GET /auth/google`
2. Backend redirects to Google
3. Google redirects to `GET /auth/google/callback`
4. Backend validates state, creates/logs in user, sets `sid` cookie
5. Backend returns JSON success response (default) or redirects to frontend if redirect URLs are configured

Google callback can optionally redirect to frontend after setting the cookie when these env vars are configured:
- `GOOGLE_OAUTH_SUCCESS_REDIRECT_URL`
- `GOOGLE_OAUTH_ERROR_REDIRECT_URL`

If not configured, the callback returns JSON success/error responses (default behavior).

## Vault Encryption Model

- Server-managed encryption (not zero-knowledge)
- Backend encrypts `payload` before writing to DB
- Backend decrypts payload for `GET /vault/items/:id`
- Algorithm: `AES-256-GCM`

Vault item list endpoint returns metadata only (no decrypted secrets).

## Rate Limiting

- Global rate-limit guard enabled via Redis
- Route policies are applied with decorators:
  - `@AuthRateLimit()` for stricter auth route limits
  - `@DefaultRateLimit()` for standard routes
  - `@RateLimit({...})` for custom route limits
  - `@SkipRateLimit()` to bypass for specific routes (e.g. health check)

Response headers may include:
- `X-RateLimit-Limit`
- `X-RateLimit-Remaining`
- `X-RateLimit-Reset`
- `X-RateLimit-Policy`
- `Retry-After` (when blocked)

## Common Error Codes

Generic:
- `VALIDATION_ERROR`
- `BAD_REQUEST`
- `UNAUTHORIZED`
- `FORBIDDEN`
- `NOT_FOUND`
- `CONFLICT`
- `TOO_MANY_REQUESTS`
- `INTERNAL_SERVER_ERROR`

Auth:
- `AUTH_EMAIL_ALREADY_REGISTERED`
- `AUTH_INVALID_CREDENTIALS`
- `AUTH_UNAUTHORIZED`
- `AUTH_SESSION_INVALID`
- `AUTH_ACCOUNT_DISABLED`
- `AUTH_CURRENT_PASSWORD_REQUIRED`
- `AUTH_CURRENT_PASSWORD_INVALID`
- `AUTH_OAUTH_STATE_INVALID`
- `AUTH_OAUTH_GOOGLE_EXCHANGE_FAILED`
- `AUTH_OAUTH_GOOGLE_PROFILE_FAILED`
- `AUTH_OAUTH_GOOGLE_EMAIL_REQUIRED`
- `AUTH_OAUTH_GOOGLE_ACCESS_DENIED`

Vault:
- `VAULT_ITEM_NOT_FOUND`
- `VAULT_DECRYPTION_FAILED`

## Testing

Unit tests currently cover:
- `AuthController`
- `AuthService` (Google OAuth and password update paths)
- `VaultController`
- `VaultService`

Run tests:

```bash
npm run test
```

Coverage:

```bash
npm run test:cov
```

## Notes for Frontend Development

- Use `credentials: 'include'` for all protected requests
- Call `GET /auth/me` on app startup to determine login state
- Handle `401` as logged out session
- Handle `429` with retry message (auth routes are rate limited more aggressively)
- Do not store vault secrets in local storage

## Roadmap (Not Implemented Yet)

- GitHub OAuth
- Session/device management endpoints (`list sessions`, `logout all devices`)
- Server-side vault pagination and filtering
- Shared/team vaults
- Zero-knowledge/client-side encryption
