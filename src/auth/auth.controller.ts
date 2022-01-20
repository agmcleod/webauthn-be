import {
  Controller,
  Get,
  Post,
  Res,
  Query,
  Body,
  Session,
} from '@nestjs/common'
import { Response } from 'express'

import { WebauthnService } from '../webauthn/webauthn.service'
import { UsersService } from '../users/users.service'
import { getBadRequestError } from '../utils'
import { AuthenticationRequest } from '../webauthn/dtos/authentication-request.dto'

@Controller('auth')
export class AuthController {
  constructor(
    private usersService: UsersService,
    private webauthnService: WebauthnService,
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
  async login(
    @Res() res: Response,
    @Body() body: AuthenticationRequest,
    @Session() session: Record<string, any>,
  ) {
    const user = await this.usersService.findByUsername(body.email)
    if (!user) {
      return getBadRequestError(res, 'User not found')
    }

    const result = await this.webauthnService.verifyAssertionResult(
      body.credential,
      session.challenge,
      user,
    )

    console.log(result)
  }
}
