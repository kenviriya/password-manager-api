import { z } from 'zod';

export const updatePasswordDtoSchema = z
  .object({
    currentPassword: z
      .string()
      .min(1, 'Current password cannot be empty')
      .max(128)
      .optional(),
    newPassword: z
      .string()
      .min(8, 'New password must be at least 8 characters')
      .max(128, 'New password must be at most 128 characters'),
  })
  .strict();

export type UpdatePasswordDto = z.infer<typeof updatePasswordDtoSchema>;
