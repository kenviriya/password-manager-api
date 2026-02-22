import { Logger, Provider } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import Redis, { RedisOptions } from 'ioredis';

export const REDIS_CLIENT = 'REDIS_CLIENT';
export type RedisClient = Redis;

function buildRedisOptions(configService: ConfigService): RedisOptions {
  const nodeEnv = configService.get<string>('NODE_ENV', 'development');
  const isProduction = nodeEnv === 'production';

  return {
    lazyConnect: true,
    enableReadyCheck: true,
    enableOfflineQueue: false,
    connectTimeout: 10_000,
    commandTimeout: 5_000,
    keepAlive: 30_000,
    maxRetriesPerRequest: 1,
    retryStrategy: (attempt) => Math.min(attempt * 200, 2_000),
    reconnectOnError: (error) => {
      return error.message.includes('READONLY');
    },
    showFriendlyErrorStack: !isProduction,
  };
}

function assertRedisUrl(redisUrl: string): void {
  let parsed: URL;

  try {
    parsed = new URL(redisUrl);
  } catch {
    throw new Error(
      'Invalid REDIS_URL: must be a valid redis:// or rediss:// URL',
    );
  }

  if (!['redis:', 'rediss:'].includes(parsed.protocol)) {
    throw new Error(
      'Invalid REDIS_URL: protocol must be redis:// or rediss://',
    );
  }
}

export const redisClientProvider: Provider = {
  provide: REDIS_CLIENT,
  useFactory: async (configService: ConfigService) => {
    const logger = new Logger('RedisClientProvider');
    const redisUrl = configService.getOrThrow<string>('REDIS_URL');

    assertRedisUrl(redisUrl);

    const client = new Redis(redisUrl, buildRedisOptions(configService));

    client.on('connect', () => logger.log('Connecting to Redis...'));
    client.on('ready', () => logger.log('Redis connection is ready'));
    client.on('reconnecting', () => logger.warn('Reconnecting to Redis...'));
    client.on('end', () => logger.warn('Redis connection closed'));
    client.on('error', (error) =>
      logger.error(`Redis error: ${error.message}`, error.stack),
    );

    await client.connect();
    await client.ping();

    return client;
  },
  inject: [ConfigService],
};
