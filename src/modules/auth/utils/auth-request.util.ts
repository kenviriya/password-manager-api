import type { Request } from 'express';

export function getCookie(req: Request, name: string): string | null {
  const cookieHeader = req.headers.cookie;

  if (!cookieHeader) {
    return null;
  }

  for (const part of cookieHeader.split(';')) {
    const [rawName, ...rawValueParts] = part.trim().split('=');

    if (rawName !== name) {
      continue;
    }

    return decodeURIComponent(rawValueParts.join('='));
  }

  return null;
}

export function getClientIp(req: Request): string | undefined {
  const forwarded = req.headers['x-forwarded-for'];

  if (typeof forwarded === 'string') {
    return forwarded.split(',')[0]?.trim() || undefined;
  }

  if (Array.isArray(forwarded)) {
    return forwarded[0];
  }

  return req.ip || undefined;
}
