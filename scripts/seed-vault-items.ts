import 'dotenv/config';

import { and, eq, inArray } from 'drizzle-orm';
import { drizzle } from 'drizzle-orm/node-postgres';
import { Pool } from 'pg';
import {
  createCipheriv,
  createHash,
  randomBytes,
} from 'node:crypto';

import { users, vaultItems } from '../src/common/database/schema';

const SEED_EMAIL = 'user@example.com';
const ALGORITHM = 'aes-256-gcm';
const KEY_VERSION = 1;
const IV_LENGTH = 12;

type SeedVaultPayload = {
  username?: string;
  password?: string;
  notes?: string;
  otpSecret?: string | null;
  customFields?: Array<{ key: string; value: string }>;
  [key: string]: unknown;
};

type SeedVaultItem = {
  title: string;
  itemType: string;
  websiteUrl: string | null;
  favorite: boolean;
  payload: SeedVaultPayload;
};

const SEED_ITEMS: SeedVaultItem[] = [
  {
    title: 'Seed • GitHub',
    itemType: 'login',
    websiteUrl: 'https://github.com/login',
    favorite: true,
    payload: {
      username: 'user@example.com',
      password: 'GithubPass123!',
      notes: 'Primary GitHub account',
      customFields: [{ key: 'recovery_email', value: 'user@example.com' }],
    },
  },
  {
    title: 'Seed • Gmail',
    itemType: 'login',
    websiteUrl: 'https://accounts.google.com',
    favorite: true,
    payload: {
      username: 'user@example.com',
      password: 'GmailPass123!',
      notes: 'Personal mailbox',
      otpSecret: null,
    },
  },
  {
    title: 'Seed • AWS Console',
    itemType: 'login',
    websiteUrl: 'https://signin.aws.amazon.com',
    favorite: false,
    payload: {
      username: 'user@example.com',
      password: 'AwsConsole123!',
      notes: 'Demo account only',
      customFields: [{ key: 'account_id', value: '123456789012' }],
    },
  },
  {
    title: 'Seed • Netflix',
    itemType: 'login',
    websiteUrl: 'https://www.netflix.com/login',
    favorite: false,
    payload: {
      username: 'user@example.com',
      password: 'Netflix123!',
      notes: 'Family profile owner',
    },
  },
  {
    title: 'Seed • Banking',
    itemType: 'login',
    websiteUrl: 'https://onlinebanking.example.com/login',
    favorite: false,
    payload: {
      username: 'user@example.com',
      password: 'Banking123!',
      notes: 'Mock seed data only',
      customFields: [
        { key: 'customer_id', value: 'CUST-0001' },
        { key: 'branch', value: 'Downtown' },
      ],
    },
  },
];

async function main() {
  const databaseUrl = process.env.DATABASE_URL;

  if (!databaseUrl) {
    throw new Error('DATABASE_URL is required');
  }

  const pool = new Pool({
    connectionString: databaseUrl,
    max: 1,
  });
  const db = drizzle(pool);

  try {
    const [user] = await db
      .select()
      .from(users)
      .where(eq(users.email, SEED_EMAIL))
      .limit(1);

    if (!user) {
      throw new Error(
        `Seed user not found (${SEED_EMAIL}). Run "npm run seed:user" first.`,
      );
    }

    const key = resolveVaultKey({
      vaultEncryptionKey: process.env.VAULT_ENCRYPTION_KEY,
      databaseUrl,
    });

    const now = new Date();
    const seedTitles = SEED_ITEMS.map((item) => item.title);

    await db.transaction(async (tx) => {
      await tx
        .delete(vaultItems)
        .where(
          and(
            eq(vaultItems.userId, user.id),
            inArray(vaultItems.title, seedTitles),
          ),
        );

      const rows = SEED_ITEMS.map((item) => {
        const encrypted = encryptPayload(item.payload, key);

        return {
          userId: user.id,
          title: item.title,
          itemType: item.itemType,
          websiteUrl: item.websiteUrl,
          favorite: item.favorite,
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
        };
      });

      await tx.insert(vaultItems).values(rows);
    });

    console.log('Seeded vault items successfully');
    console.log(`email: ${SEED_EMAIL}`);
    console.log(`count: ${SEED_ITEMS.length}`);
    console.log('items:');
    for (const item of SEED_ITEMS) {
      console.log(`- ${item.title}`);
    }
  } finally {
    await pool.end();
  }
}

function encryptPayload(
  payload: SeedVaultPayload,
  key: Buffer,
): {
  encryptedPayload: string;
  iv: string;
  authTag: string;
  encryptionAlgorithm: string;
  keyVersion: number;
  encryptedDataKey: string | null;
} {
  const iv = randomBytes(IV_LENGTH);
  const cipher = createCipheriv(ALGORITHM, key, iv);
  const plaintext = JSON.stringify(payload);

  const encrypted = Buffer.concat([
    cipher.update(plaintext, 'utf8'),
    cipher.final(),
  ]);

  return {
    encryptedPayload: encrypted.toString('base64'),
    iv: iv.toString('base64'),
    authTag: cipher.getAuthTag().toString('base64'),
    encryptionAlgorithm: ALGORITHM,
    keyVersion: KEY_VERSION,
    encryptedDataKey: null,
  };
}

function resolveVaultKey(input: {
  vaultEncryptionKey?: string;
  databaseUrl: string;
}): Buffer {
  const rawKey = input.vaultEncryptionKey;

  if (!rawKey) {
    return createHash('sha256').update(input.databaseUrl).digest();
  }

  return parseEncryptionKey(rawKey);
}

function parseEncryptionKey(rawKey: string): Buffer {
  if (rawKey.startsWith('base64:')) {
    return assertKeyLength(
      Buffer.from(rawKey.slice('base64:'.length), 'base64'),
    );
  }

  if (rawKey.startsWith('hex:')) {
    return assertKeyLength(Buffer.from(rawKey.slice('hex:'.length), 'hex'));
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

main().catch((error) => {
  console.error('Seed failed:', error);
  process.exitCode = 1;
});
