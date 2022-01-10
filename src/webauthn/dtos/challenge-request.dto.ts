import { IsNotEmpty } from 'class-validator'

export class ChallengeRequest {
  @IsNotEmpty()
  id: string
  @IsNotEmpty()
  rawId: string
  @IsNotEmpty()
  response: {
    authenticatorData: string
    attestationObject: string
    clientDataJSON: string
  }
  @IsNotEmpty()
  type = 'public-key'
}
