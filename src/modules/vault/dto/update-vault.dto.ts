import { z } from 'zod';

import { vaultPayloadSchema } from './create-vault.dto';

export const updateVaultDtoSchema = z
  .object({
    title: z.string().trim().min(1).max(200).optional(),
    itemType: z.string().trim().min(1).max(50).optional(),
    websiteUrl: z
      .url('websiteUrl must be a valid URL')
      .max(2000)
      .nullable()
      .optional(),
    favorite: z.boolean().optional(),
    payload: vaultPayloadSchema.optional(),
  })
  .strict()
  .refine((value) => Object.keys(value).length > 0, {
    message: 'At least one field must be provided',
    path: [],
  });

export type UpdateVaultDto = z.infer<typeof updateVaultDtoSchema>;
