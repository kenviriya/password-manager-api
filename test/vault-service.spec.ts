import { HttpStatus } from '@nestjs/common';

import { AppException } from '../src/common/errors/app.exception';
import { ERROR_CODE } from '../src/common/errors/error-codes';
import type { CreateVaultDto } from '../src/modules/vault/dto/create-vault.dto';
import type { UpdateVaultDto } from '../src/modules/vault/dto/update-vault.dto';
import type { VaultEncryptionService } from '../src/modules/vault/services/vault-encryption.service';
import { VaultService } from '../src/modules/vault/vault.service';
import type {
  EncryptedVaultPayload,
  VaultItemPayload,
} from '../src/modules/vault/types/vault.types';

type MockDb = {
  insert: jest.Mock;
  select: jest.Mock;
  update: jest.Mock;
};

type MockEncryptionService = {
  encryptPayload: jest.Mock;
  decryptPayload: jest.Mock;
};

describe('VaultService (unit)', () => {
  let service: VaultService;
  let db: MockDb;
  let encryptionService: MockEncryptionService;

  beforeEach(() => {
    db = createMockDb();
    encryptionService = createMockEncryptionService();
    service = new VaultService(
      db as never,
      encryptionService as unknown as VaultEncryptionService,
    );
  });

  describe('create', () => {
    it('encrypts payload, inserts row, and returns decrypted detail', async () => {
      const userId = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';
      const dto: CreateVaultDto = createMockCreateVaultDto();
      const encrypted = createMockEncryptedPayload();
      const row = createMockVaultRow({ userId });
      const expectedPayload = dto.payload;

      encryptionService.encryptPayload.mockReturnValue(encrypted);
      encryptionService.decryptPayload.mockReturnValue(expectedPayload);

      const { valuesMock } = mockInsertReturning(db, [row]);

      const result = await service.create(userId, dto);

      expect(encryptionService.encryptPayload).toHaveBeenCalledWith(
        dto.payload,
      );
      expect(valuesMock).toHaveBeenCalledTimes(1);
      expect(valuesMock.mock.calls[0][0]).toMatchObject({
        userId,
        title: dto.title,
        itemType: dto.itemType,
        websiteUrl: dto.websiteUrl,
        favorite: dto.favorite,
        encryptedPayload: encrypted.encryptedPayload,
        iv: encrypted.iv,
        authTag: encrypted.authTag,
        encryptionAlgorithm: encrypted.encryptionAlgorithm,
        keyVersion: encrypted.keyVersion,
        encryptedDataKey: encrypted.encryptedDataKey,
      });

      expect(result).toEqual({
        id: row.id,
        title: row.title,
        itemType: row.itemType,
        websiteUrl: row.websiteUrl,
        favorite: row.favorite,
        createdAt: row.createdAt,
        updatedAt: row.updatedAt,
        lastViewedAt: row.lastViewedAt,
        payload: expectedPayload,
      });
    });

    it('maps decrypt failure to VAULT_DECRYPTION_FAILED', async () => {
      const userId = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';
      const dto: CreateVaultDto = createMockCreateVaultDto();

      encryptionService.encryptPayload.mockReturnValue(
        createMockEncryptedPayload(),
      );
      encryptionService.decryptPayload.mockImplementation(() => {
        throw new Error('bad ciphertext');
      });

      mockInsertReturning(db, [createMockVaultRow({ userId })]);

      await expectAppException(
        service.create(userId, dto),
        HttpStatus.INTERNAL_SERVER_ERROR,
        ERROR_CODE.VAULT_DECRYPTION_FAILED,
      );
    });
  });

  describe('findAll', () => {
    it('returns metadata only and does not decrypt payloads', async () => {
      const userId = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';
      const rows = [
        createMockVaultRow({
          id: '11111111-1111-1111-1111-111111111111',
          userId,
        }),
        createMockVaultRow({
          id: '22222222-2222-2222-2222-222222222222',
          userId,
        }),
      ];

      mockSelectOrderBy(db, rows);

      const result = await service.findAll(userId);

      expect(encryptionService.decryptPayload).not.toHaveBeenCalled();
      expect(result).toEqual(
        rows.map((row) => ({
          id: row.id,
          title: row.title,
          itemType: row.itemType,
          websiteUrl: row.websiteUrl,
          favorite: row.favorite,
          createdAt: row.createdAt,
          updatedAt: row.updatedAt,
          lastViewedAt: row.lastViewedAt,
        })),
      );
    });
  });

  describe('findOne', () => {
    it('loads owned item, updates lastViewedAt, and returns decrypted detail', async () => {
      const userId = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';
      const row = createMockVaultRow({ userId });
      const payload = createMockPayload({ password: 'Decrypted123!' });

      encryptionService.decryptPayload.mockReturnValue(payload);
      mockSelectLimit(db, [row]);
      const { setMock } = mockUpdateNoReturning(db);

      const result = await service.findOne(userId, row.id);

      expect(setMock).toHaveBeenCalledWith({
        lastViewedAt: expect.any(Date),
        updatedAt: row.updatedAt,
      });
      expect(encryptionService.decryptPayload).toHaveBeenCalledWith({
        encryptedPayload: row.encryptedPayload,
        iv: row.iv,
        authTag: row.authTag,
        encryptionAlgorithm: row.encryptionAlgorithm,
      });
      expect(result.payload).toEqual(payload);
      expect(result.id).toBe(row.id);
      expect(result.lastViewedAt).toEqual(expect.any(Date));
    });

    it('throws VAULT_ITEM_NOT_FOUND when item is missing', async () => {
      mockSelectLimit(db, []);

      await expectAppException(
        service.findOne(
          'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
          '33333333-3333-3333-3333-333333333333',
        ),
        HttpStatus.NOT_FOUND,
        ERROR_CODE.VAULT_ITEM_NOT_FOUND,
      );
    });
  });

  describe('update', () => {
    it('updates metadata without re-encrypting when payload is absent', async () => {
      const userId = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';
      const row = createMockVaultRow({ userId });
      const updatedRow = createMockVaultRow({
        ...row,
        title: 'GitHub Work',
        favorite: true,
      });
      const dto: UpdateVaultDto = {
        title: 'GitHub Work',
        favorite: true,
      };

      mockSelectLimit(db, [row]);
      const { setMock } = mockUpdateReturning(db, [updatedRow]);
      encryptionService.decryptPayload.mockReturnValue(createMockPayload());

      const result = await service.update(userId, row.id, dto);

      expect(encryptionService.encryptPayload).not.toHaveBeenCalled();
      expect(setMock).toHaveBeenCalledWith(
        expect.objectContaining({
          title: 'GitHub Work',
          favorite: true,
          updatedAt: expect.any(Date),
        }),
      );
      expect(result.title).toBe('GitHub Work');
      expect(result.favorite).toBe(true);
    });

    it('re-encrypts payload when payload is provided', async () => {
      const userId = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';
      const row = createMockVaultRow({ userId });
      const dto: UpdateVaultDto = {
        payload: createMockPayload({ password: 'RotatedPass456!' }),
      };
      const encrypted = createMockEncryptedPayload({
        encryptedPayload: 'ciphertext-updated',
        iv: 'iv-updated',
        authTag: 'tag-updated',
      });
      const updatedRow = createMockVaultRow({
        ...row,
        encryptedPayload: encrypted.encryptedPayload,
        iv: encrypted.iv,
        authTag: encrypted.authTag,
      });

      mockSelectLimit(db, [row]);
      const { setMock } = mockUpdateReturning(db, [updatedRow]);
      encryptionService.encryptPayload.mockReturnValue(encrypted);
      encryptionService.decryptPayload.mockReturnValue(dto.payload);

      const result = await service.update(userId, row.id, dto);

      expect(encryptionService.encryptPayload).toHaveBeenCalledWith(
        dto.payload,
      );
      expect(setMock).toHaveBeenCalledWith(
        expect.objectContaining({
          encryptedPayload: 'ciphertext-updated',
          iv: 'iv-updated',
          authTag: 'tag-updated',
          encryptionAlgorithm: encrypted.encryptionAlgorithm,
          keyVersion: encrypted.keyVersion,
          encryptedDataKey: encrypted.encryptedDataKey,
          updatedAt: expect.any(Date),
        }),
      );
      expect(result.payload).toEqual(dto.payload);
    });

    it('throws VAULT_ITEM_NOT_FOUND when updating missing item', async () => {
      mockSelectLimit(db, []);

      await expectAppException(
        service.update(
          'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
          '44444444-4444-4444-4444-444444444444',
          { favorite: true },
        ),
        HttpStatus.NOT_FOUND,
        ERROR_CODE.VAULT_ITEM_NOT_FOUND,
      );
    });
  });

  describe('remove', () => {
    it('soft-deletes owned item', async () => {
      const userId = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';
      const row = createMockVaultRow({ userId });

      mockSelectLimit(db, [row]);
      const { setMock } = mockUpdateNoReturning(db);

      await service.remove(userId, row.id);

      expect(setMock).toHaveBeenCalledWith({
        deletedAt: expect.any(Date),
        updatedAt: expect.any(Date),
      });
    });

    it('throws VAULT_ITEM_NOT_FOUND when deleting missing item', async () => {
      mockSelectLimit(db, []);

      await expectAppException(
        service.remove(
          'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
          '55555555-5555-5555-5555-555555555555',
        ),
        HttpStatus.NOT_FOUND,
        ERROR_CODE.VAULT_ITEM_NOT_FOUND,
      );
    });
  });
});

function createMockDb(): MockDb {
  return {
    insert: jest.fn(),
    select: jest.fn(),
    update: jest.fn(),
  };
}

function createMockEncryptionService(): MockEncryptionService {
  return {
    encryptPayload: jest.fn(),
    decryptPayload: jest.fn(),
  };
}

function createMockCreateVaultDto(): CreateVaultDto {
  return {
    title: 'GitHub',
    itemType: 'login',
    websiteUrl: 'https://github.com/login',
    favorite: false,
    payload: createMockPayload(),
  };
}

function createMockPayload(
  overrides: Partial<VaultItemPayload> = {},
): VaultItemPayload {
  return {
    username: 'ken@example.com',
    password: 'SuperSecret123!',
    notes: 'personal account',
    customFields: [{ key: 'recovery_email', value: 'alt@example.com' }],
    ...overrides,
  };
}

function createMockEncryptedPayload(
  overrides: Partial<EncryptedVaultPayload> = {},
): EncryptedVaultPayload {
  return {
    encryptedPayload: 'ciphertext-base64',
    iv: 'iv-base64',
    authTag: 'auth-tag-base64',
    encryptionAlgorithm: 'aes-256-gcm',
    keyVersion: 1,
    encryptedDataKey: null,
    ...overrides,
  };
}

function createMockVaultRow(overrides: Record<string, unknown> = {}): {
  id: string;
  userId: string;
  title: string;
  itemType: string;
  websiteUrl: string | null;
  favorite: boolean;
  encryptedPayload: string;
  encryptionAlgorithm: string;
  keyVersion: number;
  encryptedDataKey: string | null;
  iv: string;
  authTag: string;
  createdAt: Date;
  updatedAt: Date;
  lastViewedAt: Date | null;
  deletedAt: Date | null;
} {
  const now = new Date('2026-02-22T12:00:00.000Z');
  const encrypted = createMockEncryptedPayload();

  return {
    id: '99999999-9999-9999-9999-999999999999',
    userId: 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
    title: 'GitHub',
    itemType: 'login',
    websiteUrl: 'https://github.com/login',
    favorite: false,
    encryptedPayload: encrypted.encryptedPayload,
    encryptionAlgorithm: encrypted.encryptionAlgorithm,
    keyVersion: encrypted.keyVersion,
    encryptedDataKey: encrypted.encryptedDataKey,
    iv: encrypted.iv,
    authTag: encrypted.authTag,
    createdAt: now,
    updatedAt: now,
    lastViewedAt: null,
    deletedAt: null,
    ...(overrides as object),
  };
}

function mockInsertReturning(db: MockDb, rows: unknown[]) {
  const returningMock = jest.fn().mockResolvedValue(rows);
  const valuesMock = jest.fn().mockReturnValue({ returning: returningMock });
  db.insert.mockReturnValueOnce({ values: valuesMock });

  return { valuesMock, returningMock };
}

function mockSelectOrderBy(db: MockDb, rows: unknown[]) {
  const orderByMock = jest.fn().mockResolvedValue(rows);
  const whereMock = jest.fn().mockReturnValue({ orderBy: orderByMock });
  const fromMock = jest.fn().mockReturnValue({ where: whereMock });
  db.select.mockReturnValueOnce({ from: fromMock });

  return { fromMock, whereMock, orderByMock };
}

function mockSelectLimit(db: MockDb, rows: unknown[]) {
  const limitMock = jest.fn().mockResolvedValue(rows);
  const whereMock = jest.fn().mockReturnValue({ limit: limitMock });
  const fromMock = jest.fn().mockReturnValue({ where: whereMock });
  db.select.mockReturnValueOnce({ from: fromMock });

  return { fromMock, whereMock, limitMock };
}

function mockUpdateNoReturning(db: MockDb) {
  const whereMock = jest.fn().mockResolvedValue(undefined);
  const setMock = jest.fn().mockReturnValue({ where: whereMock });
  db.update.mockReturnValueOnce({ set: setMock });

  return { setMock, whereMock };
}

function mockUpdateReturning(db: MockDb, rows: unknown[]) {
  const returningMock = jest.fn().mockResolvedValue(rows);
  const whereMock = jest.fn().mockReturnValue({ returning: returningMock });
  const setMock = jest.fn().mockReturnValue({ where: whereMock });
  db.update.mockReturnValueOnce({ set: setMock });

  return { setMock, whereMock, returningMock };
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
