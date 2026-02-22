import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
} from 'node:crypto';

import type {
  EncryptedVaultPayload,
  VaultItemPayload,
} from '../types/vault.types';

const ALGORITHM = 'aes-256-gcm';
const KEY_VERSION = 1;
const IV_LENGTH = 12;

@Injectable()
export class VaultEncryptionService {
  private readonly logger = new Logger(VaultEncryptionService.name);
  private readonly key: Buffer;

  constructor(private readonly configService: ConfigService) {
    const rawKey = this.configService.get<string>('VAULT_ENCRYPTION_KEY');

    if (!rawKey) {
      // Dev fallback only. Set VAULT_ENCRYPTION_KEY in production.
      this.logger.warn(
        'VAULT_ENCRYPTION_KEY is not set; deriving encryption key from DATABASE_URL (development fallback)',
      );
      const fallbackSeed = this.configService.get<string>(
        'DATABASE_URL',
        'dev',
      );
      this.key = createHash('sha256').update(fallbackSeed).digest();
      return;
    }

    this.key = parseEncryptionKey(rawKey);
  }

  encryptPayload(payload: VaultItemPayload): EncryptedVaultPayload {
    const iv = randomBytes(IV_LENGTH);
    const cipher = createCipheriv(ALGORITHM, this.key, iv);
    const plaintext = JSON.stringify(payload);

    const encrypted = Buffer.concat([
      cipher.update(plaintext, 'utf8'),
      cipher.final(),
    ]);

    const authTag = cipher.getAuthTag();

    return {
      encryptedPayload: encrypted.toString('base64'),
      iv: iv.toString('base64'),
      authTag: authTag.toString('base64'),
      encryptionAlgorithm: ALGORITHM,
      keyVersion: KEY_VERSION,
      encryptedDataKey: null,
    };
  }

  decryptPayload(
    encrypted: Pick<
      EncryptedVaultPayload,
      'encryptedPayload' | 'iv' | 'authTag' | 'encryptionAlgorithm'
    >,
  ): VaultItemPayload {
    if (encrypted.encryptionAlgorithm !== ALGORITHM) {
      throw new Error(
        `Unsupported encryption algorithm: ${encrypted.encryptionAlgorithm}`,
      );
    }

    const iv = Buffer.from(encrypted.iv, 'base64');
    const ciphertext = Buffer.from(encrypted.encryptedPayload, 'base64');
    const authTag = Buffer.from(encrypted.authTag, 'base64');
    const decipher = createDecipheriv(ALGORITHM, this.key, iv);

    decipher.setAuthTag(authTag);

    const decrypted = Buffer.concat([
      decipher.update(ciphertext),
      decipher.final(),
    ]);

    const parsed = JSON.parse(decrypted.toString('utf8'));

    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new Error('Decrypted payload is not a valid object');
    }

    return parsed as VaultItemPayload;
  }
}

function parseEncryptionKey(rawKey: string): Buffer {
  if (rawKey.startsWith('base64:')) {
    const value = Buffer.from(rawKey.slice('base64:'.length), 'base64');
    return assertKeyLength(value);
  }

  if (rawKey.startsWith('hex:')) {
    const value = Buffer.from(rawKey.slice('hex:'.length), 'hex');
    return assertKeyLength(value);
  }

  if (/^[a-fA-F0-9]{64}$/.test(rawKey)) {
    return assertKeyLength(Buffer.from(rawKey, 'hex'));
  }

  const base64Value = Buffer.from(rawKey, 'base64');
  if (base64Value.length === 32 && base64Value.toString('base64') === rawKey) {
    return base64Value;
  }

  throw new Error(
    'Invalid VAULT_ENCRYPTION_KEY. Use 32-byte key as hex (64 chars), base64, or prefixed with hex:/base64:',
  );
}

function assertKeyLength(key: Buffer): Buffer {
  if (key.length !== 32) {
    throw new Error(
      `Invalid VAULT_ENCRYPTION_KEY length: expected 32 bytes, received ${key.length}`,
    );
  }

  return key;
}
