import { HttpStatus } from '@nestjs/common';
import * as argon2 from 'argon2';

import { AppException } from '../src/common/errors/app.exception';
import { ERROR_CODE } from '../src/common/errors/error-codes';
import { AuthService } from '../src/modules/auth/auth.service';
import type { UpdatePasswordDto } from '../src/modules/auth/dto/update-password.dto';

type MockRedis = {
  set: jest.Mock;
  del: jest.Mock;
  get: jest.Mock;
};

type MockConfigService = {
  get: jest.Mock;
  getOrThrow: jest.Mock;
};

describe('AuthService.updatePassword (unit)', () => {
  let redis: MockRedis;
  let configService: MockConfigService;

  beforeEach(() => {
    redis = {
      set: jest.fn(),
      del: jest.fn(),
      get: jest.fn(),
    };
    configService = {
      get: jest.fn((_key: string, defaultValue?: unknown) => defaultValue),
      getOrThrow: jest.fn((key: string) => {
        throw new Error(`Unexpected getOrThrow(${key}) in password tests`);
      }),
    };
  });

  it('updates password for local user when current password is valid', async () => {
    const user = createUserRow();
    const currentPassword = 'OldPassword123!';
    const dto: UpdatePasswordDto = {
      currentPassword,
      newPassword: 'NewPassword456!',
    };
    const existingPasswordHash = await argon2.hash(currentPassword, {
      type: argon2.argon2id,
    });
    const credential = createCredentialRow({
      userId: user.id,
      passwordHash: existingPasswordHash,
    });

    const tx = createTxForExistingCredential(user, credential);
    const db = createDbWithTransaction(tx);
    const service = new AuthService(
      db as never,
      redis as never,
      configService as never,
    );

    await service.updatePassword(user.id, dto);

    expect(tx.insert).not.toHaveBeenCalled();

    const credentialUpdateCall = tx.__updateSetCalls.find(
      (payload) => payload && 'passwordHash' in (payload as object),
    );
    expect(credentialUpdateCall).toBeDefined();

    const passwordHash = (credentialUpdateCall as { passwordHash: string })
      .passwordHash;
    expect(typeof passwordHash).toBe('string');
    expect(passwordHash.startsWith('$argon2id$')).toBe(true);
    await expect(argon2.verify(passwordHash, dto.newPassword)).resolves.toBe(
      true,
    );

    const userUpdateCall = tx.__updateSetCalls.find(
      (payload) =>
        payload &&
        'updatedAt' in (payload as object) &&
        !('passwordHash' in (payload as object)),
    );
    expect(userUpdateCall).toBeDefined();
  });

  it('throws AUTH_CURRENT_PASSWORD_REQUIRED when local credential exists but currentPassword is missing', async () => {
    const user = createUserRow();
    const credential = createCredentialRow({
      userId: user.id,
      passwordHash: '$argon2id$mock',
    });
    const tx = createTxForExistingCredential(user, credential);
    const db = createDbWithTransaction(tx);
    const service = new AuthService(
      db as never,
      redis as never,
      configService as never,
    );

    await expectAppException(
      service.updatePassword(user.id, { newPassword: 'NewPassword456!' }),
      HttpStatus.BAD_REQUEST,
      ERROR_CODE.AUTH_CURRENT_PASSWORD_REQUIRED,
    );
  });

  it('throws AUTH_CURRENT_PASSWORD_INVALID when current password is wrong', async () => {
    const user = createUserRow();
    const credential = createCredentialRow({
      userId: user.id,
      passwordHash: await argon2.hash('RightPassword123!', {
        type: argon2.argon2id,
      }),
    });
    const tx = createTxForExistingCredential(user, credential);
    const db = createDbWithTransaction(tx);
    const service = new AuthService(
      db as never,
      redis as never,
      configService as never,
    );

    await expectAppException(
      service.updatePassword(user.id, {
        currentPassword: 'WrongPassword123!',
        newPassword: 'NewPassword456!',
      }),
      HttpStatus.UNAUTHORIZED,
      ERROR_CODE.AUTH_CURRENT_PASSWORD_INVALID,
    );
  });

  it('creates local credential and local auth account for oauth-only user', async () => {
    const user = createUserRow({
      emailVerifiedAt: new Date('2026-02-22T12:00:00.000Z'),
    });
    const tx = createTxForOauthUserWithoutLocalPassword(user);
    const db = createDbWithTransaction(tx);
    const service = new AuthService(
      db as never,
      redis as never,
      configService as never,
    );

    await service.updatePassword(user.id, { newPassword: 'NewPassword456!' });

    expect(tx.insert).toHaveBeenCalledTimes(2);

    const credentialInsert = tx.__insertValuesCalls[0] as Record<
      string,
      unknown
    >;
    expect(credentialInsert.userId).toBe(user.id);
    expect(typeof credentialInsert.passwordHash).toBe('string');
    expect(
      (credentialInsert.passwordHash as string).startsWith('$argon2id$'),
    ).toBe(true);

    const localAccountInsert = tx.__insertValuesCalls[1] as Record<
      string,
      unknown
    >;
    expect(localAccountInsert).toMatchObject({
      userId: user.id,
      provider: 'local',
      providerUserId: user.id,
      providerEmail: user.email,
      providerEmailVerified: true,
    });
  });
});

function createDbWithTransaction(
  tx: ReturnType<typeof createTxForExistingCredential>,
) {
  return {
    transaction: jest.fn(
      async (callback: (arg: typeof tx) => Promise<unknown>) => callback(tx),
    ),
  };
}

function createTxForExistingCredential(
  user: ReturnType<typeof createUserRow>,
  credential: ReturnType<typeof createCredentialRow>,
) {
  const updateSetCalls: unknown[] = [];
  const insertValuesCalls: unknown[] = [];
  const tx = {
    select: jest.fn(),
    insert: jest.fn(),
    update: jest.fn(),
    __updateSetCalls: updateSetCalls,
    __insertValuesCalls: insertValuesCalls,
  };

  tx.select
    .mockReturnValueOnce({
      from: jest.fn().mockReturnValue({
        where: jest.fn().mockReturnValue({
          limit: jest.fn().mockResolvedValue([user]),
        }),
      }),
    })
    .mockReturnValueOnce({
      from: jest.fn().mockReturnValue({
        where: jest.fn().mockReturnValue({
          limit: jest.fn().mockResolvedValue([credential]),
        }),
      }),
    });

  tx.insert.mockImplementation((_table: unknown) => ({
    values: jest.fn().mockImplementation((values: unknown) => {
      insertValuesCalls.push(values);
      return values;
    }),
  }));

  tx.update.mockImplementation((_table: unknown) => {
    const set = jest.fn().mockImplementation((values: unknown) => {
      updateSetCalls.push(values);
      return {
        where: jest.fn().mockResolvedValue(undefined),
      };
    });
    return { set };
  });

  return tx;
}

function createTxForOauthUserWithoutLocalPassword(
  user: ReturnType<typeof createUserRow>,
) {
  const updateSetCalls: unknown[] = [];
  const insertValuesCalls: unknown[] = [];
  const tx = {
    select: jest.fn(),
    insert: jest.fn(),
    update: jest.fn(),
    __updateSetCalls: updateSetCalls,
    __insertValuesCalls: insertValuesCalls,
  };

  tx.select
    .mockReturnValueOnce({
      from: jest.fn().mockReturnValue({
        where: jest.fn().mockReturnValue({
          limit: jest.fn().mockResolvedValue([user]),
        }),
      }),
    })
    .mockReturnValueOnce({
      from: jest.fn().mockReturnValue({
        where: jest.fn().mockReturnValue({
          limit: jest.fn().mockResolvedValue([]),
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

  tx.insert.mockImplementation((_table: unknown) => ({
    values: jest.fn().mockImplementation((values: unknown) => {
      insertValuesCalls.push(values);
      return values;
    }),
  }));

  tx.update.mockImplementation((_table: unknown) => {
    const set = jest.fn().mockImplementation((values: unknown) => {
      updateSetCalls.push(values);
      return {
        where: jest.fn().mockResolvedValue(values),
      };
    });
    return { set };
  });

  return tx;
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
    displayName: 'Ken',
    avatarUrl: null,
    isActive: true,
    createdAt: now,
    updatedAt: now,
    lastLoginAt: now,
    ...overrides,
  };
}

function createCredentialRow(
  overrides: Partial<{
    userId: string;
    passwordHash: string;
    createdAt: Date;
    updatedAt: Date;
    passwordUpdatedAt: Date;
  }> = {},
) {
  const now = new Date('2026-02-22T12:00:00.000Z');

  return {
    userId: 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
    passwordHash: '$argon2id$mock',
    createdAt: now,
    updatedAt: now,
    passwordUpdatedAt: now,
    ...overrides,
  };
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
