import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Patch,
  Post,
  Req,
  Res,
} from '@nestjs/common';
import type { Request, Response } from 'express';

import { AppException } from '../../common/errors/app.exception';
import { ERROR_CODE } from '../../common/errors/error-codes';
import { apiSuccess } from '../../common/http/api-response';
import { ZodValidationPipe } from '../../common/pipes/zod-validation.pipe';
import { AuthRateLimit } from '../../common/rate-limit/rate-limit.decorator';
import { AuthService } from './auth.service';
import { Auth } from './decorators/auth.decorator';
import { CurrentUser } from './decorators/current-user.decorator';
import { loginAuthDtoSchema, type LoginAuthDto } from './dto/login-auth.dto';
import {
  registerAuthDtoSchema,
  type RegisterAuthDto,
} from './dto/register-auth.dto';
import {
  updatePasswordDtoSchema,
  type UpdatePasswordDto,
} from './dto/update-password.dto';
import type { AuthenticatedRequest } from './types/auth-request.types';
import type { SafeUser } from './types/auth.types';
import { getClientIp, getCookie } from './utils/auth-request.util';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('register')
  @AuthRateLimit()
  async register(
    @Body(new ZodValidationPipe(registerAuthDtoSchema))
    body: RegisterAuthDto,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    const result = await this.authService.register(body, {
      ip: getClientIp(req),
      userAgent: req.get('user-agent') ?? undefined,
    });

    res.cookie(
      result.sessionCookieName,
      result.sessionToken,
      this.authService.getSessionCookieOptions(result.sessionTtlSeconds),
    );

    return apiSuccess({ user: result.user }, 'Registered successfully');
  }

  @Post('login')
  @AuthRateLimit()
  @HttpCode(200)
  async login(
    @Body(new ZodValidationPipe(loginAuthDtoSchema))
    body: LoginAuthDto,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    const result = await this.authService.login(body, {
      ip: getClientIp(req),
      userAgent: req.get('user-agent') ?? undefined,
    });

    res.cookie(
      result.sessionCookieName,
      result.sessionToken,
      this.authService.getSessionCookieOptions(result.sessionTtlSeconds),
    );

    return apiSuccess({ user: result.user }, 'Logged in successfully');
  }

  @Get('google')
  @AuthRateLimit()
  async google(@Res() res: Response) {
    const start = await this.authService.createGoogleOauthStart();

    res.cookie(
      start.stateCookieName,
      start.state,
      this.authService.getOauthStateCookieOptions(start.stateTtlSeconds),
    );

    return res.redirect(start.authorizationUrl);
  }

  @Get('google/callback')
  @AuthRateLimit()
  async googleCallback(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    const oauthStateCookieName = this.authService.getOauthStateCookieName();

    try {
      const { code, state, error } = parseGoogleOauthCallbackQuery(req);

      if (error) {
        throw new AppException(HttpStatus.UNAUTHORIZED, {
          message: 'Google OAuth was denied or failed',
          code: ERROR_CODE.AUTH_OAUTH_GOOGLE_ACCESS_DENIED,
          details: { providerError: error },
        });
      }

      if (!code || !state) {
        throw new AppException(HttpStatus.BAD_REQUEST, {
          message: 'Missing Google OAuth callback parameters',
          code: ERROR_CODE.BAD_REQUEST,
        });
      }

      const oauthStateCookieValue = getCookie(req, oauthStateCookieName);

      const result = await this.authService.loginWithGoogle(
        {
          code,
          state,
          stateCookieValue: oauthStateCookieValue,
        },
        {
          ip: getClientIp(req),
          userAgent: req.get('user-agent') ?? undefined,
        },
      );

      res.clearCookie(oauthStateCookieName, {
        ...this.authService.getOauthStateCookieOptions(0),
        maxAge: undefined,
      });

      res.cookie(
        result.sessionCookieName,
        result.sessionToken,
        this.authService.getSessionCookieOptions(result.sessionTtlSeconds),
      );

      const successRedirectUrl = this.authService.getGoogleOauthSuccessRedirectUrl();

      if (successRedirectUrl) {
        res.redirect(
          buildOauthRedirectUrl(successRedirectUrl, {
            success: '1',
            provider: 'google',
          }),
        );
        return;
      }

      return apiSuccess({ user: result.user }, 'Google login successful');
    } catch (error) {
      res.clearCookie(oauthStateCookieName, {
        ...this.authService.getOauthStateCookieOptions(0),
        maxAge: undefined,
      });

      const errorRedirectUrl = this.authService.getGoogleOauthErrorRedirectUrl();

      if (errorRedirectUrl) {
        res.redirect(buildOauthErrorRedirectUrl(errorRedirectUrl, error));
        return;
      }

      throw error;
    }
  }

  @Get('me')
  @Auth()
  async me(@CurrentUser() user: SafeUser) {
    return apiSuccess({ user }, 'Authenticated user fetched');
  }

  @Patch('password')
  @Auth()
  @AuthRateLimit()
  async updatePassword(
    @CurrentUser() user: SafeUser,
    @Body(new ZodValidationPipe(updatePasswordDtoSchema))
    body: UpdatePasswordDto,
  ) {
    await this.authService.updatePassword(user.id, body);

    return apiSuccess(null, 'Password updated successfully');
  }

  @Post('logout')
  @HttpCode(200)
  async logout(
    @Req() req: AuthenticatedRequest,
    @Res({ passthrough: true }) res: Response,
  ) {
    const cookieName = this.authService.getSessionCookieName();
    const sessionToken = req.auth?.sessionToken ?? null;

    await this.authService.logout(sessionToken);

    res.clearCookie(cookieName, {
      ...this.authService.getSessionCookieOptions(0),
      maxAge: undefined,
    });

    return apiSuccess(null, 'Logged out successfully');
  }
}

function parseGoogleOauthCallbackQuery(req: Request): {
  code?: string;
  state?: string;
  error?: string;
} {
  const query = req.query as Record<string, unknown>;

  return {
    code: typeof query.code === 'string' ? query.code : undefined,
    state: typeof query.state === 'string' ? query.state : undefined,
    error: typeof query.error === 'string' ? query.error : undefined,
  };
}

function buildOauthRedirectUrl(
  baseUrl: string,
  params: Record<string, string>,
): string {
  const url = new URL(baseUrl);

  for (const [key, value] of Object.entries(params)) {
    url.searchParams.set(key, value);
  }

  return url.toString();
}

function buildOauthErrorRedirectUrl(baseUrl: string, error: unknown): string {
  const url = new URL(baseUrl);
  url.searchParams.set('provider', 'google');
  url.searchParams.set('success', '0');

  if (error instanceof AppException) {
    const response = error.getResponse();

    if (typeof response === 'object' && response !== null) {
      const payload = response as Record<string, unknown>;

      if (typeof payload.code === 'string' && payload.code.length > 0) {
        url.searchParams.set('code', payload.code);
      }

      if (typeof payload.message === 'string' && payload.message.length > 0) {
        url.searchParams.set('message', payload.message);
      }
    }

    return url.toString();
  }

  if (error instanceof Error && error.message) {
    url.searchParams.set('message', error.message);
  }

  return url.toString();
}
