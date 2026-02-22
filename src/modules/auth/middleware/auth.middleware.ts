import { Injectable, NestMiddleware } from '@nestjs/common';
import type { NextFunction, Response } from 'express';

import { AuthService } from '../auth.service';
import type { AuthenticatedRequest } from '../types/auth-request.types';
import { getCookie } from '../utils/auth-request.util';

@Injectable()
export class AuthMiddleware implements NestMiddleware {
  constructor(private readonly authService: AuthService) {}

  use(req: AuthenticatedRequest, _res: Response, next: NextFunction): void {
    const sessionToken = getCookie(
      req,
      this.authService.getSessionCookieName(),
    );

    req.auth = {
      ...(req.auth ?? {}),
      sessionToken,
    };

    next();
  }
}
