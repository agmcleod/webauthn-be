import { Module } from '@nestjs/common'

import { UsersService } from './users.service'
import { UsersController } from './users.controller'
import { WebauthnService } from '../webauthn/webauthn.service'

@Module({
  providers: [UsersService, WebauthnService],
  controllers: [UsersController],
})
export class UsersModule {}
