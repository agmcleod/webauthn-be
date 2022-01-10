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
    console.log('setting challenge', challenge)
    return {
      challenge,
      id: base64url(crypto.randomBytes(32)),
    }
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
    if (clientData.challenge !== session.challenge) {
      return res.status(400).json({
        message: ['Challenge did not match'],
        statusCode: 400,
        error: 'Bad Request',
      })
    }

    // check frontend origin
    if (clientData.origin !== 'http://localhost:3000') {
      console.log(clientData.origin)
      return res.status(400).json({
        message: ['Origin did not match'],
        statusCode: 400,
        error: 'Bad Request',
      })
    }

    if (body.response.attestationObject) {
      const result =
        this.webauthnService.verifyAuthenticatorAttestationResponse(body)
      if (result.verified) {
        // need to write to db here
        console.log(result.authrInfo)
      } else {
        return res.status(400).json({
          message: ['Cannot authenticate the signature'],
          statusCode: 400,
          error: 'Bad Request',
        })
      }
    } else if (body.response.authenticatorData) {
    } else {
      return res.status(400).json({
        message: ['Cannot determine type of response'],
        statusCode: 400,
        error: 'Bad Request',
      })
    }

    res.status(200).json({})
  }
}
