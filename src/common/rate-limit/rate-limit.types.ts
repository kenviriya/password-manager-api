import type { Request } from 'express';

export type RateLimitPolicyName = 'default' | 'auth';
export type RateLimitIdentityScope = 'ip' | 'sessionOrIp';

export type RateLimitMetadata = {
  policyName?: RateLimitPolicyName;
  limit?: number;
  windowMs?: number;
  keyPrefix?: string;
  scope?: RateLimitIdentityScope;
};

export type ResolvedRateLimitPolicy = {
  name: RateLimitPolicyName | 'custom';
  limit: number;
  windowMs: number;
  keyPrefix: string;
  scope: RateLimitIdentityScope;
};

export type RateLimitConsumeInput = {
  request: Request & { auth?: { sessionToken?: string | null } };
  controllerName: string;
  handlerName: string;
  metadata?: RateLimitMetadata;
};

export type RateLimitDecision = {
  allowed: boolean;
  key: string;
  limit: number;
  current: number;
  remaining: number;
  resetAt: number;
  retryAfterMs: number;
  windowMs: number;
  policyName: string;
};
