import { PassportStrategy } from '@nestjs/passport'
import { Injectable, UnauthorizedException } from '@nestjs/common'
import { Request } from 'express'

import { User } from '../users/dtos/user.dto'
import { UsersService } from '../users/users.service'
import { WebauthnService } from '../webauthn/webauthn.service'
import { AuthenticationRequest } from '../webauthn/dtos/authentication-request.dto'

// This custom strategy is setup as a function prototype due to the way passport
// modifies the strategy with callback functions
function WebauthnPassportStrategy(options, verify) {
  if (typeof options == 'function') {
    verify = options
    options = {}
  }
  if (!verify) {
    throw new TypeError('WebauthnPassportStrategy requires a verify callback')
  }
  this._verify = verify
}

WebauthnPassportStrategy.prototype.authenticate = function (req, options) {
  const self = this as any

  function verified(err, user, info) {
    if (err) {
      return self.error(err)
    }
    if (!user) {
      return self.fail(info)
    }
    self.success(user, info)
  }
  try {
    this._verify(req, verified)
  } catch (ex) {
    return self.error(ex)
  }
}

@Injectable()
export class WebauthnStrategy extends PassportStrategy(
  WebauthnPassportStrategy as any,
  'webauthn',
) {
  constructor(
    private webauthnService: WebauthnService,
    private usersService: UsersService,
  ) {
    super()
  }

  async validate(req: Request): Promise<User> {
    const body = req.body as AuthenticationRequest
    const user = await this.usersService.findByUsername(body.email)
    if (!user) {
      throw new UnauthorizedException()
    }

    const session = req.session as any
    try {
      await this.webauthnService.verifyAssertionResult(
        body.credential,
        session.challenge,
        user,
      )
    } catch (err) {
      console.error(err)
      throw new UnauthorizedException()
    }

    return user
  }
}
