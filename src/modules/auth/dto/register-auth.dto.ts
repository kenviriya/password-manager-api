import { z } from 'zod';

export const registerAuthDtoSchema = z
  .object({
    email: z.email().max(255),
    password: z
      .string()
      .min(8, 'Password must be at least 8 characters')
      .max(128, 'Password must be at most 128 characters'),
    displayName: z
      .string()
      .trim()
      .min(1, 'Display name cannot be empty')
      .max(100, 'Display name must be at most 100 characters')
      .optional(),
  })
  .strict();

export type RegisterAuthDto = z.infer<typeof registerAuthDtoSchema>;
