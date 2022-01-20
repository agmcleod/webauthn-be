import { IsNotEmpty } from 'class-validator'

import { AuthCredential } from './auth-credential.dto'

export class AuthenticationRequest {
  @IsNotEmpty()
  email: string
  @IsNotEmpty()
  credential: AuthCredential
}
