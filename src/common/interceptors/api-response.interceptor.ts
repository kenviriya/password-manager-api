import {
  CallHandler,
  ExecutionContext,
  Injectable,
  NestInterceptor,
} from '@nestjs/common';
import { map, Observable } from 'rxjs';

import {
  apiSuccess,
  isApiSuccessResponse,
  type ApiSuccessResponse,
} from '../http/api-response';

@Injectable()
export class ApiResponseInterceptor implements NestInterceptor {
  intercept(
    context: ExecutionContext,
    next: CallHandler,
  ): Observable<ApiSuccessResponse<unknown>> {
    const http = context.switchToHttp();
    const request = http.getRequest<{
      url?: string;
      originalUrl?: string;
      headers?: Record<string, unknown>;
    }>();

    return next.handle().pipe(
      map((data: unknown) => {
        const baseMeta = buildMeta(request);

        if (isApiSuccessResponse(data)) {
          return {
            ...data,
            meta: {
              ...baseMeta,
              ...(data.meta ?? {}),
            },
          };
        }

        return {
          ...apiSuccess(data),
          meta: baseMeta,
        };
      }),
    );
  }
}

function buildMeta(request: {
  url?: string;
  originalUrl?: string;
  headers?: Record<string, unknown>;
}) {
  const requestId =
    typeof request.headers?.['x-request-id'] === 'string'
      ? request.headers['x-request-id']
      : undefined;

  return {
    timestamp: new Date().toISOString(),
    path: request.originalUrl ?? request.url ?? '',
    ...(requestId ? { requestId } : {}),
  };
}
