import { Global, Module } from '@nestjs/common';
import { DrizzleProvider } from './database.provider';

export const DRIZZLE = 'DRIZZLE';

@Global()
@Module({
  providers: [
    DrizzleProvider,
    {
      provide: DRIZZLE,
      useFactory: (provider: DrizzleProvider) => provider.db,
      inject: [DrizzleProvider],
    },
  ],
  exports: [DRIZZLE],
})
export class DatabaseModule {}
