import { Module } from '@nestjs/common';
import { AuthModule } from '../auth/auth.module';
import { VaultService } from './vault.service';
import { VaultController } from './vault.controller';
import { VaultEncryptionService } from './services/vault-encryption.service';

@Module({
  imports: [AuthModule],
  controllers: [VaultController],
  providers: [VaultService, VaultEncryptionService],
})
export class VaultModule {}
