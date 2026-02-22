import {
  CanActivate,
  ExecutionContext,
  Injectable,
  Logger,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import type { Response } from 'express';

import { AppException } from '../errors/app.exception';
import {
  RATE_LIMIT_METADATA,
  RATE_LIMIT_SKIP_METADATA,
} from './rate-limit.constants';
import { RateLimitService } from './rate-limit.service';
import type { RateLimitDecision, RateLimitMetadata } from './rate-limit.types';

@Injectable()
export class RateLimitGuard implements CanActivate {
  private readonly logger = new Logger(RateLimitGuard.name);

  constructor(
    private readonly reflector: Reflector,
    private readonly rateLimitService: RateLimitService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    if (context.getType() !== 'http') {
      return true;
    }

    const skip = this.reflector.getAllAndOverride<boolean>(
      RATE_LIMIT_SKIP_METADATA,
      [context.getHandler(), context.getClass()],
    );

    if (skip) {
      return true;
    }

    const request = context.switchToHttp().getRequest();
    const response = context.switchToHttp().getResponse<Response>();
    const metadata = this.reflector.getAllAndOverride<
      RateLimitMetadata | undefined
    >(RATE_LIMIT_METADATA, [context.getHandler(), context.getClass()]);

    try {
      const decision = await this.rateLimitService.consume({
        request,
        controllerName: context.getClass().name,
        handlerName: context.getHandler().name,
        metadata,
      });

      this.setRateLimitHeaders(response, decision);

      if (!decision.allowed) {
        response.setHeader(
          'Retry-After',
          Math.max(Math.ceil(decision.retryAfterMs / 1000), 1),
        );
        throw this.rateLimitService.createTooManyRequestsException(decision);
      }

      return true;
    } catch (error) {
      if (error instanceof AppException) {
        throw error;
      }

      this.logger.warn(
        `Rate limit check failed; allowing request: ${
          error instanceof Error ? error.message : 'unknown error'
        }`,
      );
      return true;
    }
  }

  private setRateLimitHeaders(
    response: Response,
    decision: RateLimitDecision,
  ): void {
    response.setHeader('X-RateLimit-Limit', String(decision.limit));
    response.setHeader('X-RateLimit-Remaining', String(decision.remaining));
    response.setHeader(
      'X-RateLimit-Reset',
      String(Math.ceil(decision.resetAt / 1000)),
    );
    response.setHeader('X-RateLimit-Policy', decision.policyName);
  }
}
