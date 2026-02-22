import { applyDecorators, UseGuards } from '@nestjs/common';

import { SessionAuthGuard } from '../guards/session-auth.guard';

export function Auth() {
  return applyDecorators(UseGuards(SessionAuthGuard));
}
