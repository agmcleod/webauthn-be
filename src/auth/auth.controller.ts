import {
  Controller,
  Get,
  Post,
  Res,
  Query,
  Session,
  UseGuards,
  Request,
} from '@nestjs/common'
import { Response } from 'express'

import { WebauthnService } from '../webauthn/webauthn.service'
import { UsersService } from '../users/users.service'
import { getBadRequestError } from '../utils'
import { WebauthnGuard } from './webauthn.guard'
import { AuthService } from './auth.service'

@Controller('auth')
export class AuthController {
  constructor(
    private usersService: UsersService,
    private webauthnService: WebauthnService,
    private authService: AuthService,
  ) {}

  // gets the configuration to start login process
  @Get('login')
  async getLogin(
    @Res() res: Response,
    @Session() session: Record<string, any>,
    @Query('email') email?: string,
  ): Promise<Response> {
    if (email) {
      const user = await this.usersService.findByUsername(email)
      if (!user) {
        return getBadRequestError(res, 'User not found')
      }

      const assertionOptions = await this.webauthnService.getAssertionOptions(
        user.cred_id,
      )
      session.challenge = assertionOptions.challenge
      return res.status(200).json(assertionOptions)
    } else {
      return getBadRequestError(res, 'Email address is required')
    }
  }

  @Post('login')
  @UseGuards(WebauthnGuard)
  async login(@Request() req: any) {
    return this.authService.login(req.user)
  }
}
