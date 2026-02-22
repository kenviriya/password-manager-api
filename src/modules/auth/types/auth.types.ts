export type SafeUser = {
  id: string;
  email: string;
  emailVerifiedAt: Date | null;
  displayName: string | null;
  avatarUrl: string | null;
  isActive: boolean;
  createdAt: Date;
  updatedAt: Date;
  lastLoginAt: Date | null;
};

export type SessionRecord = {
  userId: string;
  createdAt: string;
  lastSeenAt: string;
  userAgent?: string;
  ip?: string;
};

export type SessionContext = {
  ip?: string;
  userAgent?: string;
};

export type AuthResult = {
  user: SafeUser;
  sessionToken: string;
  sessionCookieName: string;
  sessionTtlSeconds: number;
};

export type GoogleOauthStartResult = {
  authorizationUrl: string;
  state: string;
  stateCookieName: string;
  stateTtlSeconds: number;
};

export type GoogleOauthCallbackInput = {
  code: string;
  state: string;
  stateCookieValue: string | null;
};
