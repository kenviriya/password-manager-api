import {
  createParamDecorator,
  ExecutionContext,
  HttpStatus,
} from '@nestjs/common';

import { AppException } from '../../../common/errors/app.exception';
import { ERROR_CODE } from '../../../common/errors/error-codes';
import type { AuthenticatedRequest } from '../types/auth-request.types';
import type { SafeUser } from '../types/auth.types';

export const CurrentUser = createParamDecorator(
  (_data: unknown, ctx: ExecutionContext): SafeUser => {
    const req = ctx.switchToHttp().getRequest<AuthenticatedRequest>();
    const user = req.auth?.user;

    if (!user) {
      throw new AppException(HttpStatus.UNAUTHORIZED, {
        message: 'Not authenticated',
        code: ERROR_CODE.AUTH_UNAUTHORIZED,
      });
    }

    return user;
  },
);
