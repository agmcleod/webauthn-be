import { Module } from '@nestjs/common'

import { AuthController } from './auth.controller'
import { UsersService } from '../users/users.service'
import { WebauthnService } from '../webauthn/webauthn.service'

@Module({
  providers: [UsersService, WebauthnService],
  controllers: [AuthController],
})
export class AuthModule {}
