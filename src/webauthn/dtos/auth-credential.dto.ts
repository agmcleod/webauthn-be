export class AuthCredential {
  id: string
  rawId: string
  response: {
    authenticatorData: string
    clientDataJSON: string
    signature: string
    userHandle: string
  }
  type: 'public-key'
}
