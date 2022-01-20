import {
  Controller,
  Get,
  Post,
  Body,
  Session,
  Res,
  Query,
} from '@nestjs/common'
import * as crypto from 'crypto'
import * as base64 from 'base64-arraybuffer'
import { Response } from 'express'

import { ChallengeResponse } from './dtos/challenge-response.dto'
import { ChallengeRequest } from '../webauthn/dtos/challenge-request.dto'
import { WebauthnService } from '../webauthn/webauthn.service'
import { UsersService } from './users.service'
import { getBadRequestError } from '../utils'

@Controller('users')
export class UsersController {
  constructor(
    private webauthnService: WebauthnService,
    private usersService: UsersService,
  ) {}

  @Get('challenge')
  async getRegisterChallenge(
    @Session() session: Record<string, any>,
    @Res() res: Response,
    @Query('email') email?: string,
  ): Promise<Response<ChallengeResponse>> {
    if (email) {
      const user = await this.usersService.findByUsername(email)
      if (user) {
        return getBadRequestError(res, 'User by this email already registered')
      }
    }
    const options = await this.webauthnService.getAttestationOptions()
    const id = base64.encode(crypto.randomBytes(64))
    const challenge = base64.encode(options.challenge)
    session.challenge = challenge
    session.userId = id
    return res.status(200).json({
      challenge,
      id,
    })
  }

  @Post('register')
  async register(
    @Body() body: ChallengeRequest,
    @Session() session: Record<string, any>,
    @Res() res: Response,
  ) {
    const user = await this.usersService.findByUsername(body.email)
    if (user) {
      return getBadRequestError(res, 'User by this email already registered')
    }
    if (body.credential.response?.attestationObject) {
      let result
      try {
        result =
          await this.webauthnService.verifyAuthenticatorAttestationResponse(
            body.credential,
            session.challenge,
          )
      } catch (err) {
        console.error(err)
        return getBadRequestError(res, err.message)
      }

      if (result) {
        await this.usersService.registerUser(
          body.email,
          result.publicKey,
          result.counter,
          result.credId,
          session.userId,
        )
      }
    } else {
      return getBadRequestError(res, 'Cannot determine type of response')
    }

    res.status(200).json({})
  }
}
