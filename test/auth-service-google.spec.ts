import { HttpStatus } from '@nestjs/common';

import { AppException } from '../src/common/errors/app.exception';
import { ERROR_CODE } from '../src/common/errors/error-codes';
import { AuthService } from '../src/modules/auth/auth.service';
import type { GoogleOauthCallbackInput } from '../src/modules/auth/types/auth.types';

type MockDb = {
  transaction: jest.Mock;
};

type MockRedis = {
  set: jest.Mock;
  del: jest.Mock;
  get: jest.Mock;
};

type MockConfigService = {
  get: jest.Mock;
  getOrThrow: jest.Mock;
};

describe('AuthService Google OAuth (unit)', () => {
  let service: AuthService;
  let db: MockDb;
  let redis: MockRedis;
  let configService: MockConfigService;
  let fetchSpy: jest.SpiedFunction<typeof fetch>;

  beforeEach(() => {
    db = {
      transaction: jest.fn(),
    };
    redis = {
      set: jest.fn(),
      del: jest.fn(),
      get: jest.fn(),
    };
    configService = createMockConfigService();

    service = new AuthService(
      db as never,
      redis as never,
      configService as never,
    );
    fetchSpy = jest.spyOn(globalThis, 'fetch');
  });

  afterEach(() => {
    fetchSpy.mockRestore();
  });

  describe('createGoogleOauthStart', () => {
    it('stores oauth state in redis and returns Google authorization URL', async () => {
      redis.set.mockResolvedValue('OK');

      const result = await service.createGoogleOauthStart();

      expect(result.stateCookieName).toBe('oauth_google_state');
      expect(result.stateTtlSeconds).toBe(600);
      expect(result.state).toMatch(/^[a-f0-9]{32}$/);

      expect(redis.set).toHaveBeenCalledWith(
        `auth:oauth:google:state:${result.state}`,
        '1',
        'EX',
        600,
      );

      const url = new URL(result.authorizationUrl);
      expect(url.origin + url.pathname).toBe(
        'https://accounts.google.com/o/oauth2/v2/auth',
      );
      expect(url.searchParams.get('client_id')).toBe('google-client-id');
      expect(url.searchParams.get('redirect_uri')).toBe(
        'http://localhost:4200/auth/google/callback',
      );
      expect(url.searchParams.get('response_type')).toBe('code');
      expect(url.searchParams.get('scope')).toBe('openid email profile');
      expect(url.searchParams.get('state')).toBe(result.state);
    });
  });

  describe('loginWithGoogle', () => {
    it('throws AUTH_OAUTH_STATE_INVALID when cookie state does not match', async () => {
      const input: GoogleOauthCallbackInput = {
        code: 'code',
        state: 'state-1',
        stateCookieValue: 'state-2',
      };

      await expectAppException(
        service.loginWithGoogle(input),
        HttpStatus.UNAUTHORIZED,
        ERROR_CODE.AUTH_OAUTH_STATE_INVALID,
      );

      expect(redis.del).not.toHaveBeenCalled();
      expect(fetchSpy).not.toHaveBeenCalled();
      expect(db.transaction).not.toHaveBeenCalled();
    });

    it('throws AUTH_OAUTH_GOOGLE_EXCHANGE_FAILED when token exchange fails', async () => {
      const input = createGoogleCallbackInput();

      redis.del.mockResolvedValue(1);
      fetchSpy.mockResolvedValueOnce(
        createFetchResponse({ ok: false, json: { error: 'invalid_grant' } }),
      );

      await expectAppException(
        service.loginWithGoogle(input),
        HttpStatus.BAD_GATEWAY,
        ERROR_CODE.AUTH_OAUTH_GOOGLE_EXCHANGE_FAILED,
      );

      expect(redis.del).toHaveBeenCalledWith(
        `auth:oauth:google:state:${input.state}`,
      );
      expect(fetchSpy).toHaveBeenCalledTimes(1);
      expect(db.transaction).not.toHaveBeenCalled();
    });

    it('throws AUTH_OAUTH_GOOGLE_EMAIL_REQUIRED when Google email is missing/unverified', async () => {
      const input = createGoogleCallbackInput();

      redis.del.mockResolvedValue(1);
      fetchSpy
        .mockResolvedValueOnce(
          createFetchResponse({
            ok: true,
            json: { access_token: 'access-token' },
          }),
        )
        .mockResolvedValueOnce(
          createFetchResponse({
            ok: true,
            json: {
              sub: 'google-sub-123',
              email: 'ken@example.com',
              email_verified: false,
            },
          }),
        );

      await expectAppException(
        service.loginWithGoogle(input),
        HttpStatus.BAD_REQUEST,
        ERROR_CODE.AUTH_OAUTH_GOOGLE_EMAIL_REQUIRED,
      );

      expect(fetchSpy).toHaveBeenCalledTimes(2);
      expect(db.transaction).not.toHaveBeenCalled();
    });

    it('creates/links Google account, creates session, and returns auth result (new user path)', async () => {
      const input = createGoogleCallbackInput();
      const nowish = new Date('2026-02-22T12:00:00.000Z');
      const createdUser = createUserRow({
        id: 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb',
        email: 'ken@example.com',
        emailVerifiedAt: nowish,
        displayName: 'Ken Google',
        avatarUrl: 'https://example.com/avatar.png',
        lastLoginAt: nowish,
        createdAt: nowish,
        updatedAt: nowish,
      });

      redis.del.mockResolvedValue(1);
      redis.set.mockResolvedValue('OK');
      fetchSpy
        .mockResolvedValueOnce(
          createFetchResponse({
            ok: true,
            json: { access_token: 'access-token' },
          }),
        )
        .mockResolvedValueOnce(
          createFetchResponse({
            ok: true,
            json: {
              sub: 'google-sub-123',
              email: 'Ken@Example.com',
              email_verified: true,
              name: 'Ken Google',
              picture: 'https://example.com/avatar.png',
            },
          }),
        );

      const tx = createMockGoogleTxForNewUser(createdUser);
      db.transaction.mockImplementation(
        async (callback: (txArg: typeof tx) => Promise<unknown>) =>
          callback(tx),
      );

      const result = await service.loginWithGoogle(input, {
        ip: '198.51.100.50',
        userAgent: 'ChromeTest',
      });

      expect(fetchSpy).toHaveBeenCalledTimes(2);
      expect(db.transaction).toHaveBeenCalledTimes(1);
      expect(tx.insert).toHaveBeenCalledTimes(2);
      expect(redis.set).toHaveBeenCalledWith(
        expect.stringMatching(/^auth:session:/),
        expect.any(String),
        'EX',
        60 * 60 * 24 * 7,
      );

      const sessionPayload = JSON.parse(
        redis.set.mock.calls[0][1] as string,
      ) as {
        userId: string;
        ip?: string;
        userAgent?: string;
      };
      expect(sessionPayload.userId).toBe(createdUser.id);
      expect(sessionPayload.ip).toBe('198.51.100.50');
      expect(sessionPayload.userAgent).toBe('ChromeTest');

      expect(result.user).toMatchObject({
        id: createdUser.id,
        email: 'ken@example.com',
        displayName: 'Ken Google',
      });
      expect(result.sessionCookieName).toBe('sid');
      expect(result.sessionTtlSeconds).toBe(60 * 60 * 24 * 7);
      expect(result.sessionToken).toMatch(/^[a-f0-9]{64}$/);
    });
  });
});

function createMockConfigService(): MockConfigService {
  const env: Record<string, string> = {
    GOOGLE_CLIENT_ID: 'google-client-id',
    GOOGLE_CLIENT_SECRET: 'google-client-secret',
    GOOGLE_OAUTH_REDIRECT_URI: 'http://localhost:4200/auth/google/callback',
    NODE_ENV: 'development',
  };

  return {
    get: jest.fn((key: string, defaultValue?: unknown) => {
      return env[key] ?? defaultValue;
    }),
    getOrThrow: jest.fn((key: string) => {
      const value = env[key];
      if (value === undefined) {
        throw new Error(`Missing config ${key}`);
      }
      return value;
    }),
  };
}

function createGoogleCallbackInput(): GoogleOauthCallbackInput {
  return {
    code: 'google-auth-code',
    state: 'oauth-state-123',
    stateCookieValue: 'oauth-state-123',
  };
}

function createFetchResponse(options: { ok: boolean; json: unknown }) {
  return {
    ok: options.ok,
    json: jest.fn().mockResolvedValue(options.json),
  } as unknown as Response;
}

function createUserRow(
  overrides: Partial<{
    id: string;
    email: string;
    emailVerifiedAt: Date | null;
    displayName: string | null;
    avatarUrl: string | null;
    isActive: boolean;
    createdAt: Date;
    updatedAt: Date;
    lastLoginAt: Date | null;
  }> = {},
) {
  const now = new Date('2026-02-22T12:00:00.000Z');

  return {
    id: 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
    email: 'ken@example.com',
    emailVerifiedAt: null,
    displayName: null,
    avatarUrl: null,
    isActive: true,
    createdAt: now,
    updatedAt: now,
    lastLoginAt: null,
    ...overrides,
  };
}

function createMockGoogleTxForNewUser(
  createdUser: ReturnType<typeof createUserRow>,
) {
  const tx = {
    select: jest.fn(),
    insert: jest.fn(),
    update: jest.fn(),
  };

  tx.select
    .mockReturnValueOnce({
      from: jest.fn().mockReturnValue({
        innerJoin: jest.fn().mockReturnValue({
          where: jest.fn().mockReturnValue({
            limit: jest.fn().mockResolvedValue([]),
          }),
        }),
      }),
    })
    .mockReturnValueOnce({
      from: jest.fn().mockReturnValue({
        where: jest.fn().mockReturnValue({
          limit: jest.fn().mockResolvedValue([]),
        }),
      }),
    });

  const insertUsersValuesMock = jest.fn().mockReturnValue({
    returning: jest.fn().mockResolvedValue([createdUser]),
  });
  const insertAuthValuesMock = jest.fn().mockResolvedValue(undefined);

  tx.insert
    .mockReturnValueOnce({ values: insertUsersValuesMock })
    .mockReturnValueOnce({ values: insertAuthValuesMock });

  return tx;
}

async function expectAppException(
  promise: Promise<unknown>,
  status: number,
  code: string,
): Promise<void> {
  try {
    await promise;
    throw new Error('Expected promise to reject');
  } catch (error) {
    expect(error).toBeInstanceOf(AppException);
    const exception = error as AppException;
    expect(exception.getStatus()).toBe(status);
    expect(exception.getResponse()).toMatchObject({ code });
  }
}
