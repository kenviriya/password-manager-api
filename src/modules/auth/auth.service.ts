import { Inject, Injectable, HttpStatus } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { and, eq } from 'drizzle-orm';
import * as argon2 from 'argon2';
import { randomBytes } from 'node:crypto';

import { DRIZZLE } from '../../common/database/database.module';
import type { DrizzleProvider } from '../../common/database/database.provider';
import { AppException } from '../../common/errors/app.exception';
import { ERROR_CODE } from '../../common/errors/error-codes';
import {
  authAccounts,
  userCredentials,
  users,
} from '../../common/database/schema';
import { REDIS_CLIENT } from '../../common/redis/redis.provider';
import type { RedisClient } from '../../common/redis/redis.provider';
import type { LoginAuthDto } from './dto/login-auth.dto';
import type { RegisterAuthDto } from './dto/register-auth.dto';
import type { UpdatePasswordDto } from './dto/update-password.dto';
import type {
  AuthResult,
  GoogleOauthCallbackInput,
  GoogleOauthStartResult,
  SafeUser,
  SessionContext,
  SessionRecord,
} from './types/auth.types';

const SESSION_COOKIE_NAME = 'sid';
const SESSION_KEY_PREFIX = 'auth:session:';
const DEFAULT_SESSION_TTL_SECONDS = 60 * 60 * 24 * 7;
const OAUTH_STATE_COOKIE_NAME = 'oauth_google_state';
const OAUTH_STATE_REDIS_KEY_PREFIX = 'auth:oauth:google:state:';
const OAUTH_STATE_TTL_SECONDS = 60 * 10;

@Injectable()
export class AuthService {
  constructor(
    @Inject(DRIZZLE) private readonly db: DrizzleProvider['db'],
    @Inject(REDIS_CLIENT) private readonly redis: RedisClient,
    private readonly configService: ConfigService,
  ) {}

  async register(
    input: RegisterAuthDto,
    sessionContext: SessionContext = {},
  ): Promise<AuthResult> {
    const normalizedEmail = normalizeEmail(input.email);

    const [existingUser] = await this.db
      .select({ id: users.id })
      .from(users)
      .where(eq(users.email, normalizedEmail))
      .limit(1);

    if (existingUser) {
      throw new AppException(HttpStatus.CONFLICT, {
        message: 'Email is already registered',
        code: ERROR_CODE.AUTH_EMAIL_ALREADY_REGISTERED,
      });
    }

    const passwordHash = await hashPassword(input.password);
    const now = new Date();

    const createdUser = await this.db.transaction(async (tx) => {
      const [user] = await tx
        .insert(users)
        .values({
          email: normalizedEmail,
          displayName: input.displayName ?? null,
          lastLoginAt: now,
          updatedAt: now,
        })
        .returning();

      await tx.insert(userCredentials).values({
        userId: user.id,
        passwordHash,
        createdAt: now,
        updatedAt: now,
        passwordUpdatedAt: now,
      });

      await tx.insert(authAccounts).values({
        userId: user.id,
        provider: 'local',
        providerUserId: user.id,
        providerEmail: normalizedEmail,
        providerEmailVerified: false,
        createdAt: now,
        updatedAt: now,
      });

      return user;
    });

    const session = await this.createSession(createdUser.id, sessionContext);

    return {
      user: mapSafeUser(createdUser),
      sessionToken: session.token,
      sessionCookieName: SESSION_COOKIE_NAME,
      sessionTtlSeconds: session.ttlSeconds,
    };
  }

  async login(
    input: LoginAuthDto,
    sessionContext: SessionContext = {},
  ): Promise<AuthResult> {
    const normalizedEmail = normalizeEmail(input.email);

    const [record] = await this.db
      .select({
        user: users,
        credential: userCredentials,
      })
      .from(users)
      .innerJoin(userCredentials, eq(userCredentials.userId, users.id))
      .where(eq(users.email, normalizedEmail))
      .limit(1);

    if (!record) {
      throw new AppException(HttpStatus.UNAUTHORIZED, {
        message: 'Invalid email or password',
        code: ERROR_CODE.AUTH_INVALID_CREDENTIALS,
      });
    }

    if (!record.user.isActive) {
      throw new AppException(HttpStatus.FORBIDDEN, {
        message: 'Account is disabled',
        code: ERROR_CODE.AUTH_ACCOUNT_DISABLED,
      });
    }

    const isValidPassword = await verifyPassword(
      input.password,
      record.credential.passwordHash,
    );

    if (!isValidPassword) {
      throw new AppException(HttpStatus.UNAUTHORIZED, {
        message: 'Invalid email or password',
        code: ERROR_CODE.AUTH_INVALID_CREDENTIALS,
      });
    }

    const now = new Date();

    await this.db
      .update(users)
      .set({
        lastLoginAt: now,
        updatedAt: now,
      })
      .where(eq(users.id, record.user.id));

    const session = await this.createSession(record.user.id, sessionContext);

    return {
      user: {
        ...mapSafeUser(record.user),
        lastLoginAt: now,
        updatedAt: now,
      },
      sessionToken: session.token,
      sessionCookieName: SESSION_COOKIE_NAME,
      sessionTtlSeconds: session.ttlSeconds,
    };
  }

  async updatePassword(
    userId: string,
    input: UpdatePasswordDto,
  ): Promise<void> {
    const now = new Date();

    await this.db.transaction(async (tx) => {
      const [user] = await tx
        .select()
        .from(users)
        .where(eq(users.id, userId))
        .limit(1);

      if (!user || !user.isActive) {
        throw new AppException(HttpStatus.UNAUTHORIZED, {
          message: 'Not authenticated',
          code: ERROR_CODE.AUTH_UNAUTHORIZED,
        });
      }

      const [credential] = await tx
        .select()
        .from(userCredentials)
        .where(eq(userCredentials.userId, userId))
        .limit(1);

      if (credential) {
        if (!input.currentPassword) {
          throw new AppException(HttpStatus.BAD_REQUEST, {
            message: 'Current password is required',
            code: ERROR_CODE.AUTH_CURRENT_PASSWORD_REQUIRED,
          });
        }

        const isValid = await verifyPassword(
          input.currentPassword,
          credential.passwordHash,
        );

        if (!isValid) {
          throw new AppException(HttpStatus.UNAUTHORIZED, {
            message: 'Current password is incorrect',
            code: ERROR_CODE.AUTH_CURRENT_PASSWORD_INVALID,
          });
        }

        const passwordHash = await hashPassword(input.newPassword);

        await tx
          .update(userCredentials)
          .set({
            passwordHash,
            updatedAt: now,
            passwordUpdatedAt: now,
          })
          .where(eq(userCredentials.userId, userId));
      } else {
        const passwordHash = await hashPassword(input.newPassword);

        await tx.insert(userCredentials).values({
          userId,
          passwordHash,
          createdAt: now,
          updatedAt: now,
          passwordUpdatedAt: now,
        });

        const [localAccount] = await tx
          .select()
          .from(authAccounts)
          .where(
            and(
              eq(authAccounts.userId, userId),
              eq(authAccounts.provider, 'local'),
            ),
          )
          .limit(1);

        if (!localAccount) {
          await tx.insert(authAccounts).values({
            userId,
            provider: 'local',
            providerUserId: userId,
            providerEmail: user.email,
            providerEmailVerified: user.emailVerifiedAt !== null,
            createdAt: now,
            updatedAt: now,
          });
        }
      }

      await tx
        .update(users)
        .set({ updatedAt: now })
        .where(eq(users.id, userId));
    });
  }

  async createGoogleOauthStart(): Promise<GoogleOauthStartResult> {
    const clientId = this.getRequiredConfig('GOOGLE_CLIENT_ID');
    const redirectUri = this.getRequiredConfig('GOOGLE_OAUTH_REDIRECT_URI');
    const state = randomBytes(16).toString('hex');

    await this.redis.set(
      this.getGoogleOauthStateKey(state),
      '1',
      'EX',
      OAUTH_STATE_TTL_SECONDS,
    );

    const url = new URL('https://accounts.google.com/o/oauth2/v2/auth');
    url.searchParams.set('client_id', clientId);
    url.searchParams.set('redirect_uri', redirectUri);
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('scope', 'openid email profile');
    url.searchParams.set('state', state);
    url.searchParams.set('access_type', 'offline');
    url.searchParams.set('include_granted_scopes', 'true');
    url.searchParams.set('prompt', 'select_account');

    return {
      authorizationUrl: url.toString(),
      state,
      stateCookieName: OAUTH_STATE_COOKIE_NAME,
      stateTtlSeconds: OAUTH_STATE_TTL_SECONDS,
    };
  }

  async loginWithGoogle(
    input: GoogleOauthCallbackInput,
    sessionContext: SessionContext = {},
  ): Promise<AuthResult> {
    await this.consumeGoogleOauthStateOrThrow(
      input.state,
      input.stateCookieValue,
    );

    const tokens = await this.exchangeGoogleAuthCode(input.code);
    const profile = await this.fetchGoogleUserInfo(tokens.accessToken);

    if (!profile.email || profile.emailVerified !== true) {
      throw new AppException(HttpStatus.BAD_REQUEST, {
        message: 'Google account must have a verified email',
        code: ERROR_CODE.AUTH_OAUTH_GOOGLE_EMAIL_REQUIRED,
      });
    }

    const normalizedEmail = normalizeEmail(profile.email);
    const now = new Date();

    const user = await this.db.transaction(async (tx) => {
      const [googleLinked] = await tx
        .select({
          user: users,
          authAccount: authAccounts,
        })
        .from(authAccounts)
        .innerJoin(users, eq(users.id, authAccounts.userId))
        .where(
          and(
            eq(authAccounts.provider, 'google'),
            eq(authAccounts.providerUserId, profile.sub),
          ),
        )
        .limit(1);

      if (googleLinked) {
        if (!googleLinked.user.isActive) {
          throw new AppException(HttpStatus.FORBIDDEN, {
            message: 'Account is disabled',
            code: ERROR_CODE.AUTH_ACCOUNT_DISABLED,
          });
        }

        await tx
          .update(authAccounts)
          .set({
            providerEmail: normalizedEmail,
            providerEmailVerified: true,
            updatedAt: now,
          })
          .where(eq(authAccounts.id, googleLinked.authAccount.id));

        const [updatedUser] = await tx
          .update(users)
          .set({
            email: normalizedEmail,
            emailVerifiedAt: googleLinked.user.emailVerifiedAt ?? now,
            displayName: googleLinked.user.displayName ?? profile.name ?? null,
            avatarUrl: googleLinked.user.avatarUrl ?? profile.picture ?? null,
            lastLoginAt: now,
            updatedAt: now,
          })
          .where(eq(users.id, googleLinked.user.id))
          .returning();

        return updatedUser;
      }

      const [existingUser] = await tx
        .select()
        .from(users)
        .where(eq(users.email, normalizedEmail))
        .limit(1);

      if (existingUser) {
        if (!existingUser.isActive) {
          throw new AppException(HttpStatus.FORBIDDEN, {
            message: 'Account is disabled',
            code: ERROR_CODE.AUTH_ACCOUNT_DISABLED,
          });
        }

        await tx.insert(authAccounts).values({
          userId: existingUser.id,
          provider: 'google',
          providerUserId: profile.sub,
          providerEmail: normalizedEmail,
          providerEmailVerified: true,
          createdAt: now,
          updatedAt: now,
        });

        const [updatedUser] = await tx
          .update(users)
          .set({
            emailVerifiedAt: existingUser.emailVerifiedAt ?? now,
            displayName: existingUser.displayName ?? profile.name ?? null,
            avatarUrl: existingUser.avatarUrl ?? profile.picture ?? null,
            lastLoginAt: now,
            updatedAt: now,
          })
          .where(eq(users.id, existingUser.id))
          .returning();

        return updatedUser;
      }

      const [createdUser] = await tx
        .insert(users)
        .values({
          email: normalizedEmail,
          emailVerifiedAt: now,
          displayName: profile.name ?? null,
          avatarUrl: profile.picture ?? null,
          lastLoginAt: now,
          updatedAt: now,
        })
        .returning();

      await tx.insert(authAccounts).values({
        userId: createdUser.id,
        provider: 'google',
        providerUserId: profile.sub,
        providerEmail: normalizedEmail,
        providerEmailVerified: true,
        createdAt: now,
        updatedAt: now,
      });

      return createdUser;
    });

    const session = await this.createSession(user.id, sessionContext);

    return {
      user: mapSafeUser(user),
      sessionToken: session.token,
      sessionCookieName: SESSION_COOKIE_NAME,
      sessionTtlSeconds: session.ttlSeconds,
    };
  }

  async getCurrentUser(sessionToken: string | null): Promise<SafeUser> {
    if (!sessionToken) {
      throw new AppException(HttpStatus.UNAUTHORIZED, {
        message: 'Not authenticated',
        code: ERROR_CODE.AUTH_UNAUTHORIZED,
      });
    }

    const session = await this.readSession(sessionToken);

    if (!session) {
      throw new AppException(HttpStatus.UNAUTHORIZED, {
        message: 'Session is invalid or expired',
        code: ERROR_CODE.AUTH_SESSION_INVALID,
      });
    }

    const [user] = await this.db
      .select()
      .from(users)
      .where(eq(users.id, session.userId))
      .limit(1);

    if (!user || !user.isActive) {
      await this.deleteSession(sessionToken);
      throw new AppException(HttpStatus.UNAUTHORIZED, {
        message: 'Session is invalid or expired',
        code: ERROR_CODE.AUTH_SESSION_INVALID,
      });
    }

    await this.touchSession(sessionToken, session);

    return mapSafeUser(user);
  }

  async logout(sessionToken: string | null): Promise<void> {
    if (!sessionToken) {
      return;
    }

    await this.deleteSession(sessionToken);
  }

  getSessionCookieName(): string {
    return SESSION_COOKIE_NAME;
  }

  getSessionCookieOptions(ttlSeconds: number) {
    const isProduction =
      this.configService.get<string>('NODE_ENV', 'development') ===
      'production';

    return {
      httpOnly: true,
      secure: isProduction,
      sameSite: 'lax' as const,
      path: '/',
      maxAge: ttlSeconds * 1000,
    };
  }

  getOauthStateCookieName(): string {
    return OAUTH_STATE_COOKIE_NAME;
  }

  getOauthStateCookieOptions(ttlSeconds: number) {
    const isProduction =
      this.configService.get<string>('NODE_ENV', 'development') ===
      'production';

    return {
      httpOnly: true,
      secure: isProduction,
      sameSite: 'lax' as const,
      path: '/',
      maxAge: ttlSeconds * 1000,
    };
  }

  getGoogleOauthSuccessRedirectUrl(): string | null {
    const value = this.configService.get<string>(
      'GOOGLE_OAUTH_SUCCESS_REDIRECT_URL',
    );

    return normalizeOptionalUrl(value);
  }

  getGoogleOauthErrorRedirectUrl(): string | null {
    const value = this.configService.get<string>(
      'GOOGLE_OAUTH_ERROR_REDIRECT_URL',
    );

    return normalizeOptionalUrl(value);
  }

  private getSessionTtlSeconds(): number {
    const raw = this.configService.get<string>('AUTH_SESSION_TTL_SECONDS');
    const parsed = raw ? Number.parseInt(raw, 10) : NaN;

    if (Number.isFinite(parsed) && parsed > 0) {
      return parsed;
    }

    return DEFAULT_SESSION_TTL_SECONDS;
  }

  private async createSession(userId: string, context: SessionContext) {
    const token = randomBytes(32).toString('hex');
    const nowIso = new Date().toISOString();
    const ttlSeconds = this.getSessionTtlSeconds();
    const payload: SessionRecord = {
      userId,
      createdAt: nowIso,
      lastSeenAt: nowIso,
      ...(context.userAgent ? { userAgent: context.userAgent } : {}),
      ...(context.ip ? { ip: context.ip } : {}),
    };

    await this.redis.set(
      this.getSessionKey(token),
      JSON.stringify(payload),
      'EX',
      ttlSeconds,
    );

    return { token, ttlSeconds };
  }

  private async readSession(token: string): Promise<SessionRecord | null> {
    const raw = await this.redis.get(this.getSessionKey(token));

    if (!raw) {
      return null;
    }

    try {
      return JSON.parse(raw) as SessionRecord;
    } catch {
      await this.deleteSession(token);
      return null;
    }
  }

  private async touchSession(
    token: string,
    session: SessionRecord,
  ): Promise<void> {
    const ttlSeconds = this.getSessionTtlSeconds();
    const next: SessionRecord = {
      ...session,
      lastSeenAt: new Date().toISOString(),
    };

    await this.redis.set(
      this.getSessionKey(token),
      JSON.stringify(next),
      'EX',
      ttlSeconds,
    );
  }

  private async deleteSession(token: string): Promise<void> {
    await this.redis.del(this.getSessionKey(token));
  }

  private getSessionKey(token: string): string {
    return `${SESSION_KEY_PREFIX}${token}`;
  }

  private getGoogleOauthStateKey(state: string): string {
    return `${OAUTH_STATE_REDIS_KEY_PREFIX}${state}`;
  }

  private async consumeGoogleOauthStateOrThrow(
    state: string,
    stateCookieValue: string | null,
  ): Promise<void> {
    if (!state || !stateCookieValue || state !== stateCookieValue) {
      throw new AppException(HttpStatus.UNAUTHORIZED, {
        message: 'Invalid OAuth state',
        code: ERROR_CODE.AUTH_OAUTH_STATE_INVALID,
      });
    }

    const deleted = await this.redis.del(this.getGoogleOauthStateKey(state));

    if (deleted === 0) {
      throw new AppException(HttpStatus.UNAUTHORIZED, {
        message: 'Invalid or expired OAuth state',
        code: ERROR_CODE.AUTH_OAUTH_STATE_INVALID,
      });
    }
  }

  private async exchangeGoogleAuthCode(
    code: string,
  ): Promise<{ accessToken: string }> {
    const clientId = this.getRequiredConfig('GOOGLE_CLIENT_ID');
    const clientSecret = this.getRequiredConfig('GOOGLE_CLIENT_SECRET');
    const redirectUri = this.getRequiredConfig('GOOGLE_OAUTH_REDIRECT_URI');

    const response = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        code,
        client_id: clientId,
        client_secret: clientSecret,
        redirect_uri: redirectUri,
        grant_type: 'authorization_code',
      }),
    });

    if (!response.ok) {
      throw new AppException(HttpStatus.BAD_GATEWAY, {
        message: 'Failed to exchange Google OAuth code',
        code: ERROR_CODE.AUTH_OAUTH_GOOGLE_EXCHANGE_FAILED,
      });
    }

    const data = (await response.json()) as {
      access_token?: string;
    };

    if (!data.access_token) {
      throw new AppException(HttpStatus.BAD_GATEWAY, {
        message: 'Google OAuth token response did not include access token',
        code: ERROR_CODE.AUTH_OAUTH_GOOGLE_EXCHANGE_FAILED,
      });
    }

    return {
      accessToken: data.access_token,
    };
  }

  private async fetchGoogleUserInfo(
    accessToken: string,
  ): Promise<GoogleUserInfo> {
    const response = await fetch(
      'https://openidconnect.googleapis.com/v1/userinfo',
      {
        headers: {
          authorization: `Bearer ${accessToken}`,
        },
      },
    );

    if (!response.ok) {
      throw new AppException(HttpStatus.BAD_GATEWAY, {
        message: 'Failed to fetch Google profile',
        code: ERROR_CODE.AUTH_OAUTH_GOOGLE_PROFILE_FAILED,
      });
    }

    const data = (await response.json()) as Partial<GoogleUserInfo>;

    if (!data.sub) {
      throw new AppException(HttpStatus.BAD_GATEWAY, {
        message: 'Google profile response missing subject',
        code: ERROR_CODE.AUTH_OAUTH_GOOGLE_PROFILE_FAILED,
      });
    }

    return {
      sub: data.sub,
      email: data.email,
      emailVerified: data.emailVerified ?? data.email_verified ?? false,
      name: data.name,
      picture: data.picture,
    };
  }

  private getRequiredConfig(key: string): string {
    return this.configService.getOrThrow<string>(key);
  }
}

function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

function normalizeOptionalUrl(value: string | undefined): string | null {
  if (!value) {
    return null;
  }

  const trimmed = value.trim();

  return trimmed.length > 0 ? trimmed : null;
}

function mapSafeUser(user: typeof users.$inferSelect): SafeUser {
  return {
    id: user.id,
    email: user.email,
    emailVerifiedAt: user.emailVerifiedAt ?? null,
    displayName: user.displayName ?? null,
    avatarUrl: user.avatarUrl ?? null,
    isActive: user.isActive,
    createdAt: user.createdAt,
    updatedAt: user.updatedAt,
    lastLoginAt: user.lastLoginAt ?? null,
  };
}

async function hashPassword(password: string): Promise<string> {
  return argon2.hash(password, {
    type: argon2.argon2id,
    memoryCost: 19_456,
    timeCost: 2,
    parallelism: 1,
  });
}

async function verifyPassword(
  password: string,
  storedHash: string,
): Promise<boolean> {
  try {
    return await argon2.verify(storedHash, password);
  } catch {
    return false;
  }
}

type GoogleUserInfo = {
  sub: string;
  email?: string;
  emailVerified?: boolean;
  email_verified?: boolean;
  name?: string;
  picture?: string;
};
