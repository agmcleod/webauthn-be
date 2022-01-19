import { Injectable } from '@nestjs/common'
import { Fido2Lib, AttestationResult } from 'fido2-lib'
import * as base64url from 'base64-arraybuffer'

import { Credential } from './dtos/credential.dto'

@Injectable()
export class WebauthnService {
  f2l: Fido2Lib

  constructor() {
    this.f2l = new Fido2Lib({
      rpId: 'localhost',
      rpName: 'webauthn test',
      challengeSize: 32,
    })
  }

  async verifyAuthenticatorAttestationResponse(
    webAuthnResponse: Credential,
    challenge: string,
  ) {
    const attestationResult: AttestationResult = {
      rawId: base64url.decode(webAuthnResponse.rawId),
      id: base64url.decode(webAuthnResponse.id),
      response: webAuthnResponse.response,
    }
    return this.f2l.attestationResult(attestationResult, {
      challenge,
      origin: 'http://localhost:3000',
      factor: 'either',
    })
  }
}
