import {
  boolean,
  index,
  integer,
  pgTable,
  text,
  timestamp,
  uuid,
} from 'drizzle-orm/pg-core';

import { users } from './user.schema';

export const vaultItems = pgTable(
  'vault_items',
  {
    id: uuid('id').defaultRandom().primaryKey(),

    userId: uuid('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),

    title: text('title').notNull(),

    itemType: text('item_type').notNull().default('login'),

    websiteUrl: text('website_url'),

    favorite: boolean('favorite').notNull().default(false),

    encryptedPayload: text('encrypted_payload').notNull(),

    encryptionAlgorithm: text('encryption_algorithm')
      .notNull()
      .default('aes-256-gcm'),

    keyVersion: integer('key_version').notNull().default(1),

    encryptedDataKey: text('encrypted_data_key'),

    iv: text('iv').notNull(),

    authTag: text('auth_tag').notNull(),

    createdAt: timestamp('created_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
    updatedAt: timestamp('updated_at', { withTimezone: true })
      .notNull()
      .defaultNow(),

    lastViewedAt: timestamp('last_viewed_at', { withTimezone: true }),

    deletedAt: timestamp('deleted_at', { withTimezone: true }),
  },
  (t) => [
    index('vault_items_user_id_idx').on(t.userId),

    index('vault_items_user_updated_at_idx').on(t.userId, t.updatedAt),

    index('vault_items_user_type_idx').on(t.userId, t.itemType),
  ],
);
