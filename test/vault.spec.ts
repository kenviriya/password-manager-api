import { HttpStatus } from '@nestjs/common';

import { AppException } from '../src/common/errors/app.exception';
import { ERROR_CODE } from '../src/common/errors/error-codes';
import { VaultController } from '../src/modules/vault/vault.controller';
import type { CreateVaultDto } from '../src/modules/vault/dto/create-vault.dto';
import type { UpdateVaultDto } from '../src/modules/vault/dto/update-vault.dto';
import type {
  VaultItemDetail,
  VaultItemMetadata,
} from '../src/modules/vault/types/vault.types';
import type { SafeUser } from '../src/modules/auth/types/auth.types';

type MockVaultService = {
  create: jest.Mock;
  findAll: jest.Mock;
  findOne: jest.Mock;
  update: jest.Mock;
  remove: jest.Mock;
};

describe('VaultController (unit)', () => {
  let controller: VaultController;
  let vaultService: MockVaultService;
  let user: SafeUser;

  beforeEach(() => {
    vaultService = createMockVaultService();
    controller = new VaultController(vaultService as never);
    user = createMockUser();
  });

  describe('create', () => {
    it('returns success response with created item', async () => {
      const dto: CreateVaultDto = createMockCreateVaultDto();
      const item = createMockVaultDetail();

      vaultService.create.mockResolvedValue(item);

      const response = await controller.create(user, dto);

      expect(vaultService.create).toHaveBeenCalledWith(user.id, dto);
      expect(response).toEqual({
        success: true,
        message: 'Vault item created',
        data: { item },
      });
    });

    it('propagates service error', async () => {
      const dto: CreateVaultDto = createMockCreateVaultDto();
      const error = new AppException(HttpStatus.INTERNAL_SERVER_ERROR, {
        message: 'Failed to decrypt vault item',
        code: ERROR_CODE.VAULT_DECRYPTION_FAILED,
      });

      vaultService.create.mockRejectedValue(error);

      await expect(controller.create(user, dto)).rejects.toBe(error);
    });
  });

  describe('findAll', () => {
    it('returns success response with metadata list and pagination meta', async () => {
      const items: VaultItemMetadata[] = [
        createMockVaultMetadata({ id: '11111111-1111-1111-1111-111111111111' }),
        createMockVaultMetadata({ id: '22222222-2222-2222-2222-222222222222' }),
      ];

      vaultService.findAll.mockResolvedValue(items);

      const response = await controller.findAll(user);

      expect(vaultService.findAll).toHaveBeenCalledWith(user.id);
      expect(response).toEqual({
        success: true,
        message: 'Vault items fetched',
        data: { items },
        meta: { pagination: { total: 2 } },
      });
    });

    it('returns empty list with zero total', async () => {
      vaultService.findAll.mockResolvedValue([]);

      const response = await controller.findAll(user);

      expect(response).toEqual({
        success: true,
        message: 'Vault items fetched',
        data: { items: [] },
        meta: { pagination: { total: 0 } },
      });
    });

    it('propagates service error', async () => {
      const error = new AppException(HttpStatus.INTERNAL_SERVER_ERROR, {
        message: 'Unexpected error',
        code: ERROR_CODE.INTERNAL_SERVER_ERROR,
      });

      vaultService.findAll.mockRejectedValue(error);

      await expect(controller.findAll(user)).rejects.toBe(error);
    });
  });

  describe('findOne', () => {
    it('returns success response with item detail', async () => {
      const item = createMockVaultDetail();
      const itemId = item.id;

      vaultService.findOne.mockResolvedValue(item);

      const response = await controller.findOne(user, itemId);

      expect(vaultService.findOne).toHaveBeenCalledWith(user.id, itemId);
      expect(response).toEqual({
        success: true,
        message: 'Vault item fetched',
        data: { item },
      });
    });

    it('propagates not found error', async () => {
      const error = new AppException(HttpStatus.NOT_FOUND, {
        message: 'Vault item not found',
        code: ERROR_CODE.VAULT_ITEM_NOT_FOUND,
      });

      vaultService.findOne.mockRejectedValue(error);

      await expect(
        controller.findOne(user, '33333333-3333-3333-3333-333333333333'),
      ).rejects.toBe(error);
    });
  });

  describe('update', () => {
    it('returns success response with updated item', async () => {
      const itemId = '44444444-4444-4444-4444-444444444444';
      const dto: UpdateVaultDto = {
        favorite: true,
        payload: {
          username: 'ken@example.com',
          password: 'UpdatedPass123!',
          notes: 'rotated',
        },
      };
      const item = createMockVaultDetail({
        id: itemId,
        favorite: true,
        payload: dto.payload,
      });

      vaultService.update.mockResolvedValue(item);

      const response = await controller.update(user, itemId, dto);

      expect(vaultService.update).toHaveBeenCalledWith(user.id, itemId, dto);
      expect(response).toEqual({
        success: true,
        message: 'Vault item updated',
        data: { item },
      });
    });

    it('propagates service error', async () => {
      const itemId = '55555555-5555-5555-5555-555555555555';
      const dto: UpdateVaultDto = { favorite: true };
      const error = new AppException(HttpStatus.NOT_FOUND, {
        message: 'Vault item not found',
        code: ERROR_CODE.VAULT_ITEM_NOT_FOUND,
      });

      vaultService.update.mockRejectedValue(error);

      await expect(controller.update(user, itemId, dto)).rejects.toBe(error);
    });
  });

  describe('remove', () => {
    it('returns success response after delete', async () => {
      const itemId = '66666666-6666-6666-6666-666666666666';

      vaultService.remove.mockResolvedValue(undefined);

      const response = await controller.remove(user, itemId);

      expect(vaultService.remove).toHaveBeenCalledWith(user.id, itemId);
      expect(response).toEqual({
        success: true,
        message: 'Vault item deleted',
        data: null,
      });
    });

    it('propagates not found error', async () => {
      const itemId = '77777777-7777-7777-7777-777777777777';
      const error = new AppException(HttpStatus.NOT_FOUND, {
        message: 'Vault item not found',
        code: ERROR_CODE.VAULT_ITEM_NOT_FOUND,
      });

      vaultService.remove.mockRejectedValue(error);

      await expect(controller.remove(user, itemId)).rejects.toBe(error);
    });
  });
});

function createMockVaultService(): MockVaultService {
  return {
    create: jest.fn(),
    findAll: jest.fn(),
    findOne: jest.fn(),
    update: jest.fn(),
    remove: jest.fn(),
  };
}

function createMockUser(): SafeUser {
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
  };
}

function createMockCreateVaultDto(): CreateVaultDto {
  return {
    title: 'GitHub',
    itemType: 'login',
    websiteUrl: 'https://github.com/login',
    favorite: false,
    payload: {
      username: 'ken@example.com',
      password: 'SuperSecret123!',
      notes: 'personal',
      customFields: [{ key: 'recovery_email', value: 'alt@example.com' }],
    },
  };
}

function createMockVaultMetadata(
  overrides: Partial<VaultItemMetadata> = {},
): VaultItemMetadata {
  const now = new Date('2026-02-22T12:00:00.000Z');

  return {
    id: '88888888-8888-8888-8888-888888888888',
    title: 'GitHub',
    itemType: 'login',
    websiteUrl: 'https://github.com/login',
    favorite: false,
    createdAt: now,
    updatedAt: now,
    lastViewedAt: null,
    ...overrides,
  };
}

function createMockVaultDetail(
  overrides: Partial<VaultItemDetail> = {},
): VaultItemDetail {
  return {
    ...createMockVaultMetadata(),
    payload: {
      username: 'ken@example.com',
      password: 'SuperSecret123!',
      notes: 'personal',
    },
    ...overrides,
  };
}
