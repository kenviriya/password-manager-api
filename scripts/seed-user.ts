import 'dotenv/config';

import * as argon2 from 'argon2';
import { and, eq } from 'drizzle-orm';
import { drizzle } from 'drizzle-orm/node-postgres';
import { Pool } from 'pg';

import { authAccounts, userCredentials, users } from '../src/common/database/schema';

const SEED_EMAIL = 'user@example.com';
const SEED_PASSWORD = 'password';

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
    const normalizedEmail = SEED_EMAIL.trim().toLowerCase();
    const passwordHash = await hashPassword(SEED_PASSWORD);
    const now = new Date();

    const user = await db.transaction(async (tx) => {
      const [existingUser] = await tx
        .select()
        .from(users)
        .where(eq(users.email, normalizedEmail))
        .limit(1);

      const userRow =
        existingUser ??
        (
          await tx
            .insert(users)
            .values({
              email: normalizedEmail,
              displayName: 'Seed User',
              isActive: true,
              updatedAt: now,
            })
            .returning()
        )[0];

      const [existingCredential] = await tx
        .select()
        .from(userCredentials)
        .where(eq(userCredentials.userId, userRow.id))
        .limit(1);

      if (existingCredential) {
        await tx
          .update(userCredentials)
          .set({
            passwordHash,
            updatedAt: now,
            passwordUpdatedAt: now,
          })
          .where(eq(userCredentials.userId, userRow.id));
      } else {
        await tx.insert(userCredentials).values({
          userId: userRow.id,
          passwordHash,
          createdAt: now,
          updatedAt: now,
          passwordUpdatedAt: now,
        });
      }

      const [localAccount] = await tx
        .select()
        .from(authAccounts)
        .where(
          and(
            eq(authAccounts.userId, userRow.id),
            eq(authAccounts.provider, 'local'),
          ),
        )
        .limit(1);

      if (!localAccount) {
        await tx.insert(authAccounts).values({
          userId: userRow.id,
          provider: 'local',
          providerUserId: userRow.id,
          providerEmail: normalizedEmail,
          providerEmailVerified: false,
          createdAt: now,
          updatedAt: now,
        });
      } else {
        await tx
          .update(authAccounts)
          .set({
            providerEmail: normalizedEmail,
            updatedAt: now,
          })
          .where(eq(authAccounts.id, localAccount.id));
      }

      await tx
        .update(users)
        .set({
          email: normalizedEmail,
          isActive: true,
          updatedAt: now,
        })
        .where(eq(users.id, userRow.id));

      const [freshUser] = await tx
        .select()
        .from(users)
        .where(eq(users.id, userRow.id))
        .limit(1);

      return freshUser;
    });

    console.log('Seeded user successfully');
    console.log(`email: ${SEED_EMAIL}`);
    console.log(`password: ${SEED_PASSWORD}`);
    console.log(`userId: ${user.id}`);
  } finally {
    await pool.end();
  }
}

async function hashPassword(password: string): Promise<string> {
  return argon2.hash(password, {
    type: argon2.argon2id,
    memoryCost: 19_456,
    timeCost: 2,
    parallelism: 1,
  });
}

main().catch((error) => {
  console.error('Seed failed:', error);
  process.exitCode = 1;
});
