import { z } from 'zod';

export const loginAuthDtoSchema = z
  .object({
    email: z.email().max(255),
    password: z.string().min(1, 'Password is required').max(128),
  })
  .strict();

export type LoginAuthDto = z.infer<typeof loginAuthDtoSchema>;
