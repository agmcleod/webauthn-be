import { Injectable } from '@nestjs/common'
import { Fido2Lib, AttestationResult, AssertionResult } from 'fido2-lib'
import * as base64url from 'base64-arraybuffer'

import { AuthCredential } from './dtos/auth-credential.dto'
import { Credential } from './dtos/credential.dto'
import { User } from '../users/dtos/user.dto'

@Injectable()
export class WebauthnService {
  f2l: Fido2Lib

  constructor() {
    this.f2l = new Fido2Lib({
      rpId: 'localhost',
      rpName: 'webauthn test',
    })
  }

  async getAssertionOptions(credId: string) {
    const options = await this.f2l.assertionOptions()

    return {
      challenge: base64url.encode(options.challenge),
      allowCredentials: [
        {
          id: credId,
          type: 'public-key',
        },
      ],
    }
  }

  async getAttestationOptions() {
    return await this.f2l.attestationOptions()
  }

  async verifyAssertionResult(
    authenticationRequest: AuthCredential,
    challenge: string,
    user: User,
  ) {
    const assertionResult: AssertionResult = {
      rawId: base64url.decode(authenticationRequest.rawId),
      id: base64url.decode(authenticationRequest.id),
      response: {
        ...authenticationRequest.response,
        authenticatorData: base64url.decode(
          authenticationRequest.response.authenticatorData,
        ),
      },
    }

    const result = await this.f2l.assertionResult(assertionResult, {
      challenge,
      origin: 'http://localhost:3000',
      factor: 'either',
      publicKey: user.public_key,
      prevCounter: user.counter,
      userHandle: user.cred_user_id,
    })
    return result
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
    const result = await this.f2l.attestationResult(attestationResult, {
      challenge,
      origin: 'http://localhost:3000',
      factor: 'either',
    })

    console.log(result)

    return {
      publicKey: result.authnrData.get('credentialPublicKeyPem'),
      counter: result.authnrData.get('counter'),
      credId: base64url.encode(result.authnrData.get('credId')),
    }
  }
}
