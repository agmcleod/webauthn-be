import { Controller, Get } from '@nestjs/common'
import * as crypto from 'crypto'
import base64url from 'base64url'

import { ChallengeResponse } from './dtos/challenge-response.dto'

@Controller('users')
export class UsersController {
  @Get('challenge')
  async getRegisterChallenge(): Promise<ChallengeResponse> {
    // spec mentions to persist this for the operation, not sure how yet
    // https://w3c.github.io/webauthn/#sctn-cryptographic-challenges
    return {
      challenge: base64url(crypto.randomBytes(32)),
      id: base64url(crypto.randomBytes(32)),
    }
  }
}
