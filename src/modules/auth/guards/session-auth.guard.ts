import { CanActivate, ExecutionContext, Injectable } from '@nestjs/common';

import { AuthService } from '../auth.service';
import type { AuthenticatedRequest } from '../types/auth-request.types';
import { getCookie } from '../utils/auth-request.util';

@Injectable()
export class SessionAuthGuard implements CanActivate {
  constructor(private readonly authService: AuthService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const req = context.switchToHttp().getRequest<AuthenticatedRequest>();

    const sessionToken =
      req.auth?.sessionToken ??
      getCookie(req, this.authService.getSessionCookieName());

    const user = await this.authService.getCurrentUser(sessionToken);

    req.auth = {
      ...(req.auth ?? {}),
      sessionToken,
      user,
    };

    return true;
  }
}
