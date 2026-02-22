import { HttpException } from '@nestjs/common';

import type { ErrorCode } from './error-codes';

type AppExceptionBody = {
  message: string;
  code: ErrorCode;
  details?: unknown;
};

export class AppException extends HttpException {
  constructor(statusCode: number, body: AppExceptionBody) {
    super(
      {
        message: body.message,
        code: body.code,
        ...(body.details !== undefined ? { details: body.details } : {}),
      },
      statusCode,
    );
  }
}
