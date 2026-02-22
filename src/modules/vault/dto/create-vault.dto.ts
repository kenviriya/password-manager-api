import { z } from 'zod';

const optionalTrimmedString = (max: number) =>
  z
    .string()
    .trim()
    .max(max)
    .transform((value) => (value.length === 0 ? undefined : value))
    .optional();

const customFieldSchema = z
  .object({
    key: z.string().trim().min(1).max(100),
    value: z.string().max(5000),
  })
  .strict();

export const vaultPayloadSchema = z
  .object({
    username: optionalTrimmedString(255),
    password: optionalTrimmedString(2048),
    notes: optionalTrimmedString(20_000),
    otpSecret: z.string().trim().max(255).nullable().optional(),
    customFields: z.array(customFieldSchema).max(50).optional(),
  })
  .passthrough();

export const createVaultDtoSchema = z
  .object({
    title: z.string().trim().min(1).max(200),
    itemType: z.string().trim().min(1).max(50).default('login'),
    websiteUrl: z
      .string()
      .trim()
      .url('websiteUrl must be a valid URL')
      .max(2000)
      .optional(),
    favorite: z.boolean().default(false),
    payload: vaultPayloadSchema,
  })
  .strict();

export type CreateVaultDto = z.infer<typeof createVaultDtoSchema>;
