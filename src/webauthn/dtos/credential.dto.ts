export class Credential {
  id: string
  rawId: string
  response: {
    authenticatorData: string
    attestationObject: string
    clientDataJSON: string
  }
  type: 'public-key'
}
