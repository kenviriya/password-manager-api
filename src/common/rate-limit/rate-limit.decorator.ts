import { SetMetadata } from '@nestjs/common';

import {
  RATE_LIMIT_METADATA,
  RATE_LIMIT_SKIP_METADATA,
} from './rate-limit.constants';
import type { RateLimitMetadata } from './rate-limit.types';

export function RateLimit(
  config: RateLimitMetadata,
): MethodDecorator & ClassDecorator {
  return SetMetadata(RATE_LIMIT_METADATA, config);
}

export function AuthRateLimit(): MethodDecorator & ClassDecorator {
  return RateLimit({ policyName: 'auth' });
}

export function DefaultRateLimit(): MethodDecorator & ClassDecorator {
  return RateLimit({ policyName: 'default' });
}

export function SkipRateLimit(): MethodDecorator & ClassDecorator {
  return SetMetadata(RATE_LIMIT_SKIP_METADATA, true);
}
