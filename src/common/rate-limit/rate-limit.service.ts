import { HttpStatus, Inject, Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { Request } from 'express';

import { AppException } from '../errors/app.exception';
import { ERROR_CODE } from '../errors/error-codes';
import { REDIS_CLIENT } from '../redis/redis.provider';
import type { RedisClient } from '../redis/redis.provider';
import type {
  RateLimitConsumeInput,
  RateLimitDecision,
  RateLimitMetadata,
  RateLimitPolicyName,
  ResolvedRateLimitPolicy,
} from './rate-limit.types';

const RATE_LIMIT_REDIS_PREFIX = 'rate-limit';

// Atomic increment + TTL initialization for a fixed-window counter.
const CONSUME_RATE_LIMIT_LUA = `
local current = redis.call('INCR', KEYS[1])
if current == 1 then
  redis.call('PEXPIRE', KEYS[1], ARGV[1])
end
local ttl = redis.call('PTTL', KEYS[1])
if ttl < 0 then
  redis.call('PEXPIRE', KEYS[1], ARGV[1])
  ttl = tonumber(ARGV[1])
end
return { current, ttl }
`;

type ConfiguredPolicies = Record<RateLimitPolicyName, ResolvedRateLimitPolicy>;

@Injectable()
export class RateLimitService {
  private readonly logger = new Logger(RateLimitService.name);

  constructor(
    @Inject(REDIS_CLIENT) private readonly redis: RedisClient,
    private readonly configService: ConfigService,
  ) {}

  async consume(input: RateLimitConsumeInput): Promise<RateLimitDecision> {
    const policy = this.resolvePolicy(input.metadata);
    const identity = this.resolveIdentity(input.request, policy);
    const scope = `${input.controllerName}.${input.handlerName}`;
    const key = [
      RATE_LIMIT_REDIS_PREFIX,
      policy.keyPrefix,
      scope,
      identity,
    ].join(':');

    const result = await this.redis.eval(
      CONSUME_RATE_LIMIT_LUA,
      1,
      key,
      String(policy.windowMs),
    );

    const [currentRaw, ttlRaw] = Array.isArray(result)
      ? result
      : [0, policy.windowMs];
    const current = toPositiveInteger(currentRaw, 0);
    const ttlMs = Math.max(toPositiveInteger(ttlRaw, policy.windowMs), 1);
    const remaining = Math.max(policy.limit - current, 0);
    const retryAfterMs = ttlMs;
    const resetAt = Date.now() + ttlMs;
    const allowed = current <= policy.limit;

    return {
      allowed,
      key,
      limit: policy.limit,
      current,
      remaining,
      resetAt,
      retryAfterMs,
      windowMs: policy.windowMs,
      policyName: policy.name,
    };
  }

  createTooManyRequestsException(decision: RateLimitDecision): AppException {
    const retryAfterSeconds = Math.max(
      Math.ceil(decision.retryAfterMs / 1000),
      1,
    );

    return new AppException(HttpStatus.TOO_MANY_REQUESTS, {
      message: 'Too many requests, please try again later',
      code: ERROR_CODE.TOO_MANY_REQUESTS,
      details: {
        limit: decision.limit,
        remaining: decision.remaining,
        retryAfterSeconds,
        resetAt: new Date(decision.resetAt).toISOString(),
        policy: decision.policyName,
      },
    });
  }

  private resolvePolicy(metadata?: RateLimitMetadata): ResolvedRateLimitPolicy {
    const basePolicies = this.getConfiguredPolicies();
    const policyName = metadata?.policyName ?? 'default';
    const base = basePolicies[policyName];

    if (!base) {
      this.logger.warn(
        `Unknown rate limit policy "${policyName}", using default`,
      );
      return basePolicies.default;
    }

    const limit = metadata?.limit ?? base.limit;
    const windowMs = metadata?.windowMs ?? base.windowMs;
    const keyPrefix = metadata?.keyPrefix ?? base.keyPrefix;
    const scope = metadata?.scope ?? base.scope;

    return {
      name:
        metadata?.limit !== undefined ||
        metadata?.windowMs !== undefined ||
        metadata?.keyPrefix !== undefined ||
        metadata?.scope !== undefined
          ? 'custom'
          : base.name,
      limit: sanitizePositiveInteger(limit, base.limit),
      windowMs: sanitizePositiveInteger(windowMs, base.windowMs),
      keyPrefix,
      scope,
    };
  }

  private getConfiguredPolicies(): ConfiguredPolicies {
    const defaultLimit = sanitizePositiveInteger(
      this.configService.get<number>('RATE_LIMIT_DEFAULT_LIMIT', 120),
      120,
    );
    const defaultWindowSeconds = sanitizePositiveInteger(
      this.configService.get<number>('RATE_LIMIT_DEFAULT_WINDOW_SECONDS', 60),
      60,
    );
    const authLimit = sanitizePositiveInteger(
      this.configService.get<number>('RATE_LIMIT_AUTH_LIMIT', 10),
      10,
    );
    const authWindowSeconds = sanitizePositiveInteger(
      this.configService.get<number>('RATE_LIMIT_AUTH_WINDOW_SECONDS', 60),
      60,
    );

    return {
      default: {
        name: 'default',
        limit: defaultLimit,
        windowMs: defaultWindowSeconds * 1000,
        keyPrefix: 'default',
        scope: 'sessionOrIp',
      },
      auth: {
        name: 'auth',
        limit: authLimit,
        windowMs: authWindowSeconds * 1000,
        keyPrefix: 'auth',
        scope: 'ip',
      },
    };
  }

  private resolveIdentity(
    request: Request & { auth?: { sessionToken?: string | null } },
    policy: ResolvedRateLimitPolicy,
  ): string {
    const sessionToken = request.auth?.sessionToken;

    if (
      policy.scope === 'sessionOrIp' &&
      typeof sessionToken === 'string' &&
      sessionToken.length > 0
    ) {
      return `sid:${sessionToken}`;
    }

    return `ip:${getClientIp(request)}`;
  }
}

function sanitizePositiveInteger(value: unknown, fallback: number): number {
  const num = Number(value);

  if (!Number.isFinite(num)) {
    return fallback;
  }

  const normalized = Math.floor(num);
  return normalized > 0 ? normalized : fallback;
}

function toPositiveInteger(value: unknown, fallback: number): number {
  const num = Number(value);

  if (!Number.isFinite(num)) {
    return fallback;
  }

  return Math.max(Math.floor(num), 0);
}

function getClientIp(request: Request): string {
  const forwardedFor = request.headers['x-forwarded-for'];
  const rawForwarded =
    typeof forwardedFor === 'string'
      ? forwardedFor
      : Array.isArray(forwardedFor)
        ? forwardedFor[0]
        : undefined;
  const forwardedIp = rawForwarded?.split(',')[0]?.trim();

  if (forwardedIp) {
    return forwardedIp;
  }

  if (typeof request.ip === 'string' && request.ip.length > 0) {
    return request.ip;
  }

  const socketIp = request.socket?.remoteAddress;
  if (typeof socketIp === 'string' && socketIp.length > 0) {
    return socketIp;
  }

  return 'unknown';
}
