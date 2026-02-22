import {
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  Param,
  ParseUUIDPipe,
  Patch,
  Post,
} from '@nestjs/common';

import { apiSuccess } from '../../common/http/api-response';
import { ZodValidationPipe } from '../../common/pipes/zod-validation.pipe';
import { Auth } from '../auth/decorators/auth.decorator';
import { CurrentUser } from '../auth/decorators/current-user.decorator';
import type { SafeUser } from '../auth/types/auth.types';
import {
  createVaultDtoSchema,
  type CreateVaultDto,
} from './dto/create-vault.dto';
import {
  updateVaultDtoSchema,
  type UpdateVaultDto,
} from './dto/update-vault.dto';
import { VaultService } from './vault.service';

@Controller('vault/items')
@Auth()
export class VaultController {
  constructor(private readonly vaultService: VaultService) {}

  @Post()
  async create(
    @CurrentUser() user: SafeUser,
    @Body(new ZodValidationPipe(createVaultDtoSchema))
    body: CreateVaultDto,
  ) {
    const item = await this.vaultService.create(user.id, body);

    return apiSuccess({ item }, 'Vault item created');
  }

  @Get()
  async findAll(@CurrentUser() user: SafeUser) {
    const items = await this.vaultService.findAll(user.id);

    return apiSuccess({ items }, 'Vault items fetched', {
      pagination: { total: items.length },
    });
  }

  @Get(':id')
  async findOne(
    @CurrentUser() user: SafeUser,
    @Param('id', new ParseUUIDPipe()) id: string,
  ) {
    const item = await this.vaultService.findOne(user.id, id);

    return apiSuccess({ item }, 'Vault item fetched');
  }

  @Patch(':id')
  async update(
    @CurrentUser() user: SafeUser,
    @Param('id', new ParseUUIDPipe()) id: string,
    @Body(new ZodValidationPipe(updateVaultDtoSchema))
    body: UpdateVaultDto,
  ) {
    const item = await this.vaultService.update(user.id, id, body);

    return apiSuccess({ item }, 'Vault item updated');
  }

  @Delete(':id')
  @HttpCode(200)
  async remove(
    @CurrentUser() user: SafeUser,
    @Param('id', new ParseUUIDPipe()) id: string,
  ) {
    await this.vaultService.remove(user.id, id);

    return apiSuccess(null, 'Vault item deleted');
  }
}
