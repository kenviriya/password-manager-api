import { HttpStatus } from '@nestjs/common';
import type { ExecutionContext } from '@nestjs/common';
import type { Request, Response } from 'express';

import { AppException } from '../src/common/errors/app.exception';
import { ERROR_CODE } from '../src/common/errors/error-codes';
import { AuthController } from '../src/modules/auth/auth.controller';
import { SessionAuthGuard } from '../src/modules/auth/guards/session-auth.guard';
import type { AuthenticatedRequest } from '../src/modules/auth/types/auth-request.types';
import type {
  AuthResult,
  GoogleOauthStartResult,
  SafeUser,
} from '../src/modules/auth/types/auth.types';

type MockAuthService = {
  register: jest.Mock;
  login: jest.Mock;
  createGoogleOauthStart: jest.Mock;
  loginWithGoogle: jest.Mock;
  updatePassword: jest.Mock;
  logout: jest.Mock;
  getCurrentUser: jest.Mock;
  getSessionCookieName: jest.Mock;
  getSessionCookieOptions: jest.Mock;
  getOauthStateCookieName: jest.Mock;
  getOauthStateCookieOptions: jest.Mock;
  getGoogleOauthSuccessRedirectUrl: jest.Mock;
  getGoogleOauthErrorRedirectUrl: jest.Mock;
};

describe('AuthController (unit)', () => {
  let controller: AuthController;
  let authService: MockAuthService;

  beforeEach(() => {
    authService = createMockAuthService();
    controller = new AuthController(authService as never);
  });

  describe('register', () => {
    it('returns success response and sets session cookie', async () => {
      const user = createMockUser();
      const dto = {
        email: 'ken@example.com',
        password: 'StrongPass123!',
        displayName: 'Ken',
      };
      const result: AuthResult = {
        user,
        sessionToken: 'session-token-1',
        sessionCookieName: 'sid',
        sessionTtlSeconds: 3600,
      };
      const req = createMockRequest({
        headers: {
          'user-agent': 'JestAgent/1.0',
          'x-forwarded-for': '203.0.113.10, 10.0.0.2',
        },
      });
      const res = createMockResponse();
      const cookieOptions = {
        httpOnly: true,
        sameSite: 'lax',
        path: '/',
        maxAge: 3600_000,
      };

      authService.register.mockResolvedValue(result);
      authService.getSessionCookieOptions.mockReturnValue(cookieOptions);

      const response = await controller.register(
        dto,
        req as Request,
        res as unknown as Response,
      );

      expect(authService.register).toHaveBeenCalledWith(dto, {
        ip: '203.0.113.10',
        userAgent: 'JestAgent/1.0',
      });
      expect(authService.getSessionCookieOptions).toHaveBeenCalledWith(3600);
      expect(res.cookie).toHaveBeenCalledWith(
        'sid',
        'session-token-1',
        cookieOptions,
      );
      expect(response).toEqual({
        success: true,
        message: 'Registered successfully',
        data: { user },
      });
    });

    it('propagates service error and does not set cookie', async () => {
      const dto = {
        email: 'ken@example.com',
        password: 'StrongPass123!',
        displayName: 'Ken',
      };
      const req = createMockRequest();
      const res = createMockResponse();
      const error = new AppException(HttpStatus.CONFLICT, {
        message: 'Email is already registered',
        code: ERROR_CODE.AUTH_EMAIL_ALREADY_REGISTERED,
      });

      authService.register.mockRejectedValue(error);

      await expect(
        controller.register(dto, req as Request, res as unknown as Response),
      ).rejects.toBe(error);

      expect(res.cookie).not.toHaveBeenCalled();
    });
  });

  describe('login', () => {
    it('returns success response and sets session cookie', async () => {
      const user = createMockUser();
      const dto = {
        email: 'ken@example.com',
        password: 'StrongPass123!',
      };
      const result: AuthResult = {
        user,
        sessionToken: 'session-token-2',
        sessionCookieName: 'sid',
        sessionTtlSeconds: 7200,
      };
      const req = createMockRequest({
        headers: {
          'user-agent': 'ChromeTest',
          'x-forwarded-for': '198.51.100.20',
        },
      });
      const res = createMockResponse();
      const cookieOptions = {
        httpOnly: true,
        secure: false,
        sameSite: 'lax',
        path: '/',
        maxAge: 7200_000,
      };

      authService.login.mockResolvedValue(result);
      authService.getSessionCookieOptions.mockReturnValue(cookieOptions);

      const response = await controller.login(
        dto,
        req as Request,
        res as unknown as Response,
      );

      expect(authService.login).toHaveBeenCalledWith(dto, {
        ip: '198.51.100.20',
        userAgent: 'ChromeTest',
      });
      expect(res.cookie).toHaveBeenCalledWith(
        'sid',
        'session-token-2',
        cookieOptions,
      );
      expect(response).toEqual({
        success: true,
        message: 'Logged in successfully',
        data: { user },
      });
    });

    it('propagates invalid credentials error', async () => {
      const dto = {
        email: 'ken@example.com',
        password: 'bad-password',
      };
      const req = createMockRequest();
      const res = createMockResponse();
      const error = new AppException(HttpStatus.UNAUTHORIZED, {
        message: 'Invalid email or password',
        code: ERROR_CODE.AUTH_INVALID_CREDENTIALS,
      });

      authService.login.mockRejectedValue(error);

      await expect(
        controller.login(dto, req as Request, res as unknown as Response),
      ).rejects.toBe(error);

      expect(res.cookie).not.toHaveBeenCalled();
    });
  });

  describe('me', () => {
    it('returns current user success envelope', async () => {
      const user = createMockUser();

      const response = await controller.me(user);

      expect(response).toEqual({
        success: true,
        message: 'Authenticated user fetched',
        data: { user },
      });
    });
  });

  describe('updatePassword', () => {
    it('calls service and returns success envelope', async () => {
      const user = createMockUser();
      const dto = {
        currentPassword: 'OldPassword123!',
        newPassword: 'NewPassword456!',
      };

      authService.updatePassword.mockResolvedValue(undefined);

      const response = await controller.updatePassword(user, dto);

      expect(authService.updatePassword).toHaveBeenCalledWith(user.id, dto);
      expect(response).toEqual({
        success: true,
        message: 'Password updated successfully',
        data: null,
      });
    });

    it('propagates service error', async () => {
      const user = createMockUser();
      const dto = {
        currentPassword: 'WrongPassword123!',
        newPassword: 'NewPassword456!',
      };
      const error = new AppException(HttpStatus.UNAUTHORIZED, {
        message: 'Current password is incorrect',
        code: ERROR_CODE.AUTH_CURRENT_PASSWORD_INVALID,
      });

      authService.updatePassword.mockRejectedValue(error);

      await expect(controller.updatePassword(user, dto)).rejects.toBe(error);
    });
  });

  describe('google', () => {
    it('sets oauth state cookie and redirects to Google auth URL', async () => {
      const res = createMockResponse();
      const start: GoogleOauthStartResult = {
        authorizationUrl:
          'https://accounts.google.com/o/oauth2/v2/auth?client_id=test',
        state: 'oauth-state-123',
        stateCookieName: 'oauth_google_state',
        stateTtlSeconds: 600,
      };
      const cookieOptions = {
        httpOnly: true,
        secure: false,
        sameSite: 'lax',
        path: '/',
        maxAge: 600_000,
      };

      authService.createGoogleOauthStart.mockResolvedValue(start);
      authService.getOauthStateCookieOptions.mockReturnValue(cookieOptions);
      res.redirect.mockReturnValue('redirected');

      const result = await controller.google(res as unknown as Response);

      expect(authService.createGoogleOauthStart).toHaveBeenCalledTimes(1);
      expect(authService.getOauthStateCookieOptions).toHaveBeenCalledWith(600);
      expect(res.cookie).toHaveBeenCalledWith(
        'oauth_google_state',
        'oauth-state-123',
        cookieOptions,
      );
      expect(res.redirect).toHaveBeenCalledWith(start.authorizationUrl);
      expect(result).toBe('redirected');
    });
  });

  describe('googleCallback', () => {
    it('returns Google login success, clears oauth state cookie, and sets session cookie', async () => {
      const user = createMockUser();
      const req = createMockRequest({
        headers: {
          cookie: 'oauth_google_state=oauth-state-abc',
          'user-agent': 'ChromeTest',
          'x-forwarded-for': '198.51.100.42',
        },
        query: {
          code: 'google-auth-code',
          state: 'oauth-state-abc',
        },
      });
      const res = createMockResponse();
      const oauthCookieOptions = {
        httpOnly: true,
        secure: false,
        sameSite: 'lax',
        path: '/',
        maxAge: 600_000,
      };
      const authResult: AuthResult = {
        user,
        sessionToken: 'session-from-google',
        sessionCookieName: 'sid',
        sessionTtlSeconds: 3600,
      };
      const sessionCookieOptions = {
        httpOnly: true,
        secure: false,
        sameSite: 'lax',
        path: '/',
        maxAge: 3_600_000,
      };

      authService.getOauthStateCookieName.mockReturnValue('oauth_google_state');
      authService.getOauthStateCookieOptions.mockReturnValue(
        oauthCookieOptions,
      );
      authService.loginWithGoogle.mockResolvedValue(authResult);
      authService.getSessionCookieOptions.mockReturnValue(sessionCookieOptions);

      const response = await controller.googleCallback(
        req as Request,
        res as unknown as Response,
      );

      expect(authService.loginWithGoogle).toHaveBeenCalledWith(
        {
          code: 'google-auth-code',
          state: 'oauth-state-abc',
          stateCookieValue: 'oauth-state-abc',
        },
        {
          ip: '198.51.100.42',
          userAgent: 'ChromeTest',
        },
      );
      expect(res.clearCookie).toHaveBeenCalledWith('oauth_google_state', {
        ...oauthCookieOptions,
        maxAge: undefined,
      });
      expect(res.cookie).toHaveBeenCalledWith(
        'sid',
        'session-from-google',
        sessionCookieOptions,
      );
      expect(response).toEqual({
        success: true,
        message: 'Google login successful',
        data: { user },
      });
    });

    it('throws access denied error when provider returns error query param', async () => {
      const req = createMockRequest({
        query: {
          error: 'access_denied',
        },
      });
      const res = createMockResponse();

      await expect(
        controller.googleCallback(req as Request, res as unknown as Response),
      ).rejects.toMatchObject({
        status: HttpStatus.UNAUTHORIZED,
      });

      expect(authService.loginWithGoogle).not.toHaveBeenCalled();
      expect(res.cookie).not.toHaveBeenCalled();
      expect(res.clearCookie).toHaveBeenCalledTimes(1);
    });

    it('throws bad request when code/state callback params are missing', async () => {
      const req = createMockRequest({ query: {} });
      const res = createMockResponse();

      await expect(
        controller.googleCallback(req as Request, res as unknown as Response),
      ).rejects.toMatchObject({
        status: HttpStatus.BAD_REQUEST,
      });

      expect(authService.loginWithGoogle).not.toHaveBeenCalled();
      expect(res.clearCookie).toHaveBeenCalledTimes(1);
    });
  });

  describe('logout', () => {
    it('logs out using session token from auth middleware and clears cookie', async () => {
      const req = createMockRequest({
        auth: { sessionToken: 'session-token-3' },
      });
      const res = createMockResponse();
      const cookieOptions = {
        httpOnly: true,
        secure: false,
        sameSite: 'lax',
        path: '/',
        maxAge: 0,
      };

      authService.getSessionCookieName.mockReturnValue('sid');
      authService.getSessionCookieOptions.mockReturnValue(cookieOptions);
      authService.logout.mockResolvedValue(undefined);

      const response = await controller.logout(req, res as unknown as Response);

      expect(authService.logout).toHaveBeenCalledWith('session-token-3');
      expect(res.clearCookie).toHaveBeenCalledWith('sid', {
        ...cookieOptions,
        maxAge: undefined,
      });
      expect(response).toEqual({
        success: true,
        message: 'Logged out successfully',
        data: null,
      });
    });

    it('propagates logout error and does not clear cookie', async () => {
      const req = createMockRequest({
        auth: { sessionToken: 'session-token-4' },
      });
      const res = createMockResponse();
      const error = new AppException(HttpStatus.UNAUTHORIZED, {
        message: 'Session is invalid or expired',
        code: ERROR_CODE.AUTH_SESSION_INVALID,
      });

      authService.getSessionCookieName.mockReturnValue('sid');
      authService.logout.mockRejectedValue(error);

      await expect(
        controller.logout(req, res as unknown as Response),
      ).rejects.toBe(error);

      expect(res.clearCookie).not.toHaveBeenCalled();
    });
  });
});

describe('SessionAuthGuard (unit)', () => {
  let guard: SessionAuthGuard;
  let authService: MockAuthService;

  beforeEach(() => {
    authService = createMockAuthService();
    guard = new SessionAuthGuard(authService as never);
  });

  it('returns true and attaches current user when session token exists on req.auth', async () => {
    const user = createMockUser();
    const req = createMockRequest({
      auth: { sessionToken: 'session-token-guard' },
    });

    authService.getCurrentUser.mockResolvedValue(user);

    const result = await guard.canActivate(createExecutionContext(req));

    expect(result).toBe(true);
    expect(authService.getCurrentUser).toHaveBeenCalledWith(
      'session-token-guard',
    );
    expect(req.auth?.user).toEqual(user);
  });

  it('reads session token from cookie header when req.auth is empty', async () => {
    const user = createMockUser();
    const req = createMockRequest({
      headers: { cookie: 'theme=light; sid=session-from-cookie; lang=en' },
    });

    authService.getSessionCookieName.mockReturnValue('sid');
    authService.getCurrentUser.mockResolvedValue(user);

    const result = await guard.canActivate(createExecutionContext(req));

    expect(result).toBe(true);
    expect(authService.getCurrentUser).toHaveBeenCalledWith(
      'session-from-cookie',
    );
    expect(req.auth?.sessionToken).toBe('session-from-cookie');
    expect(req.auth?.user).toEqual(user);
  });

  it('propagates auth error when session is invalid', async () => {
    const req = createMockRequest({
      auth: { sessionToken: 'expired-token' },
    });
    const error = new AppException(HttpStatus.UNAUTHORIZED, {
      message: 'Session is invalid or expired',
      code: ERROR_CODE.AUTH_SESSION_INVALID,
    });

    authService.getCurrentUser.mockRejectedValue(error);

    await expect(guard.canActivate(createExecutionContext(req))).rejects.toBe(
      error,
    );
  });
});

function createMockAuthService(): MockAuthService {
  return {
    register: jest.fn(),
    login: jest.fn(),
    createGoogleOauthStart: jest.fn(),
    loginWithGoogle: jest.fn(),
    updatePassword: jest.fn(),
    logout: jest.fn(),
    getCurrentUser: jest.fn(),
    getSessionCookieName: jest.fn().mockReturnValue('sid'),
    getSessionCookieOptions: jest.fn().mockReturnValue({
      httpOnly: true,
      secure: false,
      sameSite: 'lax',
      path: '/',
      maxAge: 1000,
    }),
    getOauthStateCookieName: jest.fn().mockReturnValue('oauth_google_state'),
    getOauthStateCookieOptions: jest.fn().mockReturnValue({
      httpOnly: true,
      secure: false,
      sameSite: 'lax',
      path: '/',
      maxAge: 600_000,
    }),
    getGoogleOauthSuccessRedirectUrl: jest.fn().mockReturnValue(null),
    getGoogleOauthErrorRedirectUrl: jest.fn().mockReturnValue(null),
  };
}

function createMockUser(): SafeUser {
  const now = new Date('2026-02-22T12:00:00.000Z');

  return {
    id: '11111111-1111-1111-1111-111111111111',
    email: 'ken@example.com',
    emailVerifiedAt: null,
    displayName: 'Ken',
    avatarUrl: null,
    isActive: true,
    createdAt: now,
    updatedAt: now,
    lastLoginAt: now,
  };
}

function createMockRequest(
  options: {
    headers?: Record<string, string>;
    ip?: string;
    auth?: AuthenticatedRequest['auth'];
    query?: Record<string, unknown>;
  } = {},
): AuthenticatedRequest {
  const headers = options.headers ?? {};

  const req = {
    headers,
    ip: options.ip ?? '127.0.0.1',
    auth: options.auth,
    query: options.query ?? {},
    get: jest.fn((name: string) => headers[name.toLowerCase()]),
  };

  return req as unknown as AuthenticatedRequest;
}

function createMockResponse() {
  return {
    cookie: jest.fn(),
    clearCookie: jest.fn(),
    redirect: jest.fn(),
  };
}

function createExecutionContext(req: AuthenticatedRequest): ExecutionContext {
  return {
    switchToHttp: () => ({
      getRequest: () => req,
    }),
  } as unknown as ExecutionContext;
}
