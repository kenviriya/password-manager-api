import { HttpStatus, Inject, Injectable } from '@nestjs/common';
import { and, desc, eq, isNull } from 'drizzle-orm';

import { DRIZZLE } from '../../common/database/database.module';
import type { DrizzleProvider } from '../../common/database/database.provider';
import { vaultItems } from '../../common/database/schema';
import { AppException } from '../../common/errors/app.exception';
import { ERROR_CODE } from '../../common/errors/error-codes';
import type { CreateVaultDto } from './dto/create-vault.dto';
import type { UpdateVaultDto } from './dto/update-vault.dto';
import { VaultEncryptionService } from './services/vault-encryption.service';
import type { VaultItemDetail, VaultItemMetadata } from './types/vault.types';

type VaultItemRow = typeof vaultItems.$inferSelect;
type VaultItemUpdate = Partial<typeof vaultItems.$inferInsert>;

@Injectable()
export class VaultService {
  constructor(
    @Inject(DRIZZLE) private readonly db: DrizzleProvider['db'],
    private readonly encryptionService: VaultEncryptionService,
  ) {}

  async create(userId: string, dto: CreateVaultDto): Promise<VaultItemDetail> {
    const encrypted = this.encryptionService.encryptPayload(dto.payload);
    const now = new Date();

    const [created] = await this.db
      .insert(vaultItems)
      .values({
        userId,
        title: dto.title,
        itemType: dto.itemType,
        websiteUrl: dto.websiteUrl ?? null,
        favorite: dto.favorite,
        ...encrypted,
        createdAt: now,
        updatedAt: now,
      })
      .returning();

    return this.toVaultItemDetail(created);
  }

  async findAll(userId: string): Promise<VaultItemMetadata[]> {
    const rows = await this.db
      .select()
      .from(vaultItems)
      .where(and(eq(vaultItems.userId, userId), isNull(vaultItems.deletedAt)))
      .orderBy(desc(vaultItems.updatedAt));

    return rows.map((row) => this.toVaultItemMetadata(row));
  }

  async findOne(userId: string, itemId: string): Promise<VaultItemDetail> {
    const row = await this.getActiveItemOrThrow(userId, itemId);
    const now = new Date();

    await this.db
      .update(vaultItems)
      .set({
        lastViewedAt: now,
        updatedAt: row.updatedAt,
      })
      .where(eq(vaultItems.id, row.id));

    return this.toVaultItemDetail({
      ...row,
      lastViewedAt: now,
    });
  }

  async update(
    userId: string,
    itemId: string,
    dto: UpdateVaultDto,
  ): Promise<VaultItemDetail> {
    const existing = await this.getActiveItemOrThrow(userId, itemId);
    const now = new Date();

    const updates: VaultItemUpdate = {
      updatedAt: now,
    };

    if (dto.title !== undefined) {
      updates.title = dto.title;
    }

    if (dto.itemType !== undefined) {
      updates.itemType = dto.itemType;
    }

    if (dto.websiteUrl !== undefined) {
      updates.websiteUrl = dto.websiteUrl;
    }

    if (dto.favorite !== undefined) {
      updates.favorite = dto.favorite;
    }

    if (dto.payload !== undefined) {
      const encrypted = this.encryptionService.encryptPayload(dto.payload);
      updates.encryptedPayload = encrypted.encryptedPayload;
      updates.iv = encrypted.iv;
      updates.authTag = encrypted.authTag;
      updates.encryptionAlgorithm = encrypted.encryptionAlgorithm;
      updates.keyVersion = encrypted.keyVersion;
      updates.encryptedDataKey = encrypted.encryptedDataKey;
    }

    const [updated] = await this.db
      .update(vaultItems)
      .set(updates)
      .where(eq(vaultItems.id, existing.id))
      .returning();

    return this.toVaultItemDetail(updated);
  }

  async remove(userId: string, itemId: string): Promise<void> {
    const existing = await this.getActiveItemOrThrow(userId, itemId);
    const now = new Date();

    await this.db
      .update(vaultItems)
      .set({
        deletedAt: now,
        updatedAt: now,
      })
      .where(eq(vaultItems.id, existing.id));
  }

  private async getActiveItemOrThrow(
    userId: string,
    itemId: string,
  ): Promise<VaultItemRow> {
    const [row] = await this.db
      .select()
      .from(vaultItems)
      .where(
        and(
          eq(vaultItems.id, itemId),
          eq(vaultItems.userId, userId),
          isNull(vaultItems.deletedAt),
        ),
      )
      .limit(1);

    if (!row) {
      throw new AppException(HttpStatus.NOT_FOUND, {
        message: 'Vault item not found',
        code: ERROR_CODE.VAULT_ITEM_NOT_FOUND,
      });
    }

    return row;
  }

  private toVaultItemMetadata(row: VaultItemRow): VaultItemMetadata {
    return {
      id: row.id,
      title: row.title,
      itemType: row.itemType,
      websiteUrl: row.websiteUrl ?? null,
      favorite: row.favorite,
      createdAt: row.createdAt,
      updatedAt: row.updatedAt,
      lastViewedAt: row.lastViewedAt ?? null,
    };
  }

  private toVaultItemDetail(row: VaultItemRow): VaultItemDetail {
    try {
      const payload = this.encryptionService.decryptPayload({
        encryptedPayload: row.encryptedPayload,
        iv: row.iv,
        authTag: row.authTag,
        encryptionAlgorithm: row.encryptionAlgorithm,
      });

      return {
        ...this.toVaultItemMetadata(row),
        payload,
      };
    } catch {
      throw new AppException(HttpStatus.INTERNAL_SERVER_ERROR, {
        message: 'Failed to decrypt vault item',
        code: ERROR_CODE.VAULT_DECRYPTION_FAILED,
      });
    }
  }
}
