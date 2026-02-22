import {
  Global,
  Inject,
  Injectable,
  Logger,
  Module,
  OnApplicationShutdown,
} from '@nestjs/common';
import { REDIS_CLIENT, redisClientProvider } from './redis.provider';
import type { RedisClient } from './redis.provider';

@Injectable()
class RedisLifecycleService implements OnApplicationShutdown {
  private readonly logger = new Logger(RedisLifecycleService.name);

  constructor(
    @Inject(REDIS_CLIENT) private readonly redisClient: RedisClient,
  ) {}

  async onApplicationShutdown(signal?: string): Promise<void> {
    this.logger.log(
      `Shutting down Redis client${signal ? ` (${signal})` : ''}`,
    );

    try {
      await this.redisClient.quit();
    } catch (error) {
      this.logger.warn(
        `Redis quit failed, forcing disconnect: ${(error as Error).message}`,
      );
      this.redisClient.disconnect();
    }
  }
}

@Global()
@Module({
  providers: [redisClientProvider, RedisLifecycleService],
  exports: [REDIS_CLIENT],
})
export class RedisModule {}
