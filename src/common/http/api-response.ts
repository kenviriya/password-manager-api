type ApiMeta = Record<string, unknown>;

export type ApiSuccessResponse<T> = {
  success: true;
  message: string;
  data: T;
  meta?: ApiMeta;
};

export type ApiErrorResponse = {
  success: false;
  message: string;
  error: {
    code: string;
    statusCode?: number;
    details?: unknown;
  };
  meta?: ApiMeta;
};

export function apiSuccess<T>(
  data: T,
  message = 'Success',
  meta?: ApiMeta,
): ApiSuccessResponse<T> {
  return {
    success: true,
    message,
    data,
    ...(meta ? { meta } : {}),
  };
}

export function isApiSuccessResponse(
  value: unknown,
): value is ApiSuccessResponse<unknown> {
  return (
    typeof value === 'object' &&
    value !== null &&
    'success' in value &&
    (value as { success?: unknown }).success === true &&
    'message' in value &&
    'data' in value
  );
}
