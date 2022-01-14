import { Controller, Get, Post, Body, Session, Res } from '@nestjs/common'
import * as crypto from 'crypto'
import base64url from 'base64url'
import { Response } from 'express'

import { ChallengeResponse } from './dtos/challenge-response.dto'
import { ChallengeRequest } from '../webauthn/dtos/challenge-request.dto'
import { WebauthnService } from '../webauthn/webauthn.service'

@Controller('users')
export class UsersController {
  constructor(private webauthnService: WebauthnService) {}

  @Get('challenge')
  async getRegisterChallenge(
    @Session() session: Record<string, any>,
  ): Promise<ChallengeResponse> {
    // spec mentions to persist this for the operation, not sure how yet
    // https://w3c.github.io/webauthn/#sctn-cryptographic-challenges
    const challenge = base64url(crypto.randomBytes(32))
    session.challenge = challenge
    return {
      challenge,
      id: base64url(crypto.randomBytes(32)),
    }
  }

  getBadRequestError(res: Response, message: string) {
    return res.status(400).json({
      message: [message],
      statusCode: 400,
      error: 'Bad Request',
    })
  }

  @Post('register')
  async register(
    @Body() body: ChallengeRequest,
    @Session() session: Record<string, any>,
    @Res() res: Response,
  ) {
    const clientData = JSON.parse(
      base64url.decode(body.response.clientDataJSON),
    )

    // writing these checks here instead of creating validation decorators, cause im lazy
    if (clientData.type !== 'webauthn.create') {
      return this.getBadRequestError(res, 'Incorrect client data type')
    }

    if (clientData.challenge !== session.challenge) {
      return this.getBadRequestError(res, 'Challenge did not match')
    }

    // check frontend origin
    if (clientData.origin !== 'http://localhost:3000') {
      return this.getBadRequestError(res, 'Origin did not match')
    }

    if (body.response.attestationObject) {
      const result =
        this.webauthnService.verifyAuthenticatorAttestationResponse(body)
      if (result.verified) {
        // need to write to db here
        console.log(result.authrInfo)
      } else {
        return this.getBadRequestError(res, 'Cannot authenticate the signature')
      }
    } else if (body.response.authenticatorData) {
      throw new Error('not yet implemented')
    } else {
      return this.getBadRequestError(res, 'Cannot determine type of response')
    }

    res.status(200).json({})
  }
}
