import { IsNotEmpty } from 'class-validator'

import { Credential } from './credential.dto'

export class ChallengeRequest {
  @IsNotEmpty()
  email: string
  @IsNotEmpty()
  credential: Credential
}
