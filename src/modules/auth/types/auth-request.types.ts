import type { Request } from 'express';

import type { SafeUser } from './auth.types';

export type AuthRequestContext = {
  sessionToken: string | null;
  user?: SafeUser;
};

export type AuthenticatedRequest = Request & {
  auth?: AuthRequestContext;
};
