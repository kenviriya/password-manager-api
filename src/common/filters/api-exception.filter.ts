import {
  ArgumentsHost,
  Catch,
  ExceptionFilter,
  HttpException,
  HttpStatus,
  Logger,
} from '@nestjs/common';
import type { Request, Response } from 'express';

import { ERROR_CODE, type ErrorCode } from '../errors/error-codes';
import type { ApiErrorResponse } from '../http/api-response';

@Catch()
export class ApiExceptionFilter implements ExceptionFilter {
  private readonly logger = new Logger(ApiExceptionFilter.name);

  catch(exception: unknown, host: ArgumentsHost): void {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();
    const request = ctx.getRequest<Request>();

    const parsed = this.parseException(exception);

    if (parsed.statusCode >= 500) {
      this.logger.error(
        parsed.message,
        exception instanceof Error ? exception.stack : undefined,
      );
    }

    const body: ApiErrorResponse = {
      success: false,
      message: parsed.message,
      error: {
        code: parsed.code,
        statusCode: parsed.statusCode,
        ...(parsed.details !== undefined ? { details: parsed.details } : {}),
      },
      meta: {
        timestamp: new Date().toISOString(),
        path: request.originalUrl ?? request.url,
        ...(typeof request.headers['x-request-id'] === 'string'
          ? { requestId: request.headers['x-request-id'] }
          : {}),
      },
    };

    response.status(parsed.statusCode).json(body);
  }

  private parseException(exception: unknown): {
    statusCode: number;
    message: string;
    code: ErrorCode;
    details?: unknown;
  } {
    if (exception instanceof HttpException) {
      const statusCode = exception.getStatus();
      const response = exception.getResponse();

      if (typeof response === 'string') {
        return {
          statusCode,
          message: response,
          code: mapStatusToErrorCode(statusCode),
        };
      }

      if (response && typeof response === 'object') {
        const payload = response as Record<string, unknown>;
        const message = normalizeMessage(payload.message, exception.message);
        const explicitCode =
          typeof payload.code === 'string'
            ? (payload.code as ErrorCode)
            : undefined;
        const details =
          payload.details ??
          payload.issues ??
          (Array.isArray(payload.message) ? payload.message : undefined);

        return {
          statusCode,
          message,
          code: explicitCode ?? mapStatusToErrorCode(statusCode),
          ...(details !== undefined ? { details } : {}),
        };
      }

      return {
        statusCode,
        message: exception.message,
        code: mapStatusToErrorCode(statusCode),
      };
    }

    if (exception instanceof Error) {
      return {
        statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
        message: 'Internal server error',
        code: ERROR_CODE.INTERNAL_SERVER_ERROR,
      };
    }

    return {
      statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
      message: 'Internal server error',
      code: ERROR_CODE.INTERNAL_SERVER_ERROR,
    };
  }
}

function normalizeMessage(message: unknown, fallback: string): string {
  if (typeof message === 'string' && message.length > 0) {
    return message;
  }

  if (Array.isArray(message) && message.length > 0) {
    const first = message[0];

    if (typeof first === 'string' && first.length > 0) {
      return first;
    }
  }

  return fallback || 'Request failed';
}

function mapStatusToErrorCode(statusCode: number): ErrorCode {
  switch (statusCode) {
    case HttpStatus.BAD_REQUEST:
      return ERROR_CODE.BAD_REQUEST;
    case HttpStatus.UNAUTHORIZED:
      return ERROR_CODE.UNAUTHORIZED;
    case HttpStatus.FORBIDDEN:
      return ERROR_CODE.FORBIDDEN;
    case HttpStatus.NOT_FOUND:
      return ERROR_CODE.NOT_FOUND;
    case HttpStatus.CONFLICT:
      return ERROR_CODE.CONFLICT;
    case HttpStatus.TOO_MANY_REQUESTS:
      return ERROR_CODE.TOO_MANY_REQUESTS;
    default:
      return ERROR_CODE.INTERNAL_SERVER_ERROR;
  }
}
