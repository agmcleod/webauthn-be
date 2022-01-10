import { Injectable } from '@nestjs/common'
import base64url from 'base64url'
import * as cbor from 'cbor'
import * as crypto from 'crypto'
import { Certificate } from '@fidm/x509'
import iso_3166_1 from 'iso-3166-1'

import { ChallengeRequest } from './dtos/challenge-request.dto'

const U2F_USER_PRESENTED = 0x01

// Code in this class referenced from: https://github.com/fido-alliance/webauthn-demo/blob/master/utils.js

@Injectable()
export class WebauthnService {
  /**
   * Parses authenticatorData buffer.
   * @param  {Buffer} buffer - authenticatorData buffer
   * @return {Object}        - parsed authenticatorData struct
   */
  private parseMakeCredAuthData(buffer) {
    const rpIdHash = buffer.slice(0, 32)
    buffer = buffer.slice(32)
    const flagsBuf = buffer.slice(0, 1)
    buffer = buffer.slice(1)
    const flags = flagsBuf[0]
    const counterBuf = buffer.slice(0, 4)
    buffer = buffer.slice(4)
    const counter = counterBuf.readUInt32BE(0)
    const aaguid = buffer.slice(0, 16)
    buffer = buffer.slice(16)
    const credIDLenBuf = buffer.slice(0, 2)
    buffer = buffer.slice(2)
    const credIDLen = credIDLenBuf.readUInt16BE(0)
    const credID = buffer.slice(0, credIDLen)
    buffer = buffer.slice(credIDLen)
    const COSEPublicKey = buffer

    return {
      rpIdHash,
      flagsBuf,
      flags,
      counter,
      counterBuf,
      aaguid,
      credID,
      COSEPublicKey,
    }
  }

  /**
   * Returns SHA-256 digest of the given data.
   * @param  {Buffer} data - data to hash
   * @return {Buffer}      - the hash
   */
  private hash(data) {
    return crypto.createHash('SHA256').update(data).digest()
  }

  /**
   * Takes COSE encoded public key and converts it to RAW PKCS ECDHA key
   * @param  {Buffer} COSEPublicKey - COSE encoded public key
   * @return {Buffer}               - RAW PKCS encoded public key
   */
  private COSEECDHAtoPKCS(COSEPublicKey) {
    /*
     +------+-------+-------+---------+----------------------------------+
     | name | key   | label | type    | description                      |
     |      | type  |       |         |                                  |
     +------+-------+-------+---------+----------------------------------+
     | crv  | 2     | -1    | int /   | EC Curve identifier - Taken from |
     |      |       |       | tstr    | the COSE Curves registry         |
     |      |       |       |         |                                  |
     | x    | 2     | -2    | bstr    | X Coordinate                     |
     |      |       |       |         |                                  |
     | y    | 2     | -3    | bstr /  | Y Coordinate                     |
     |      |       |       | bool    |                                  |
     |      |       |       |         |                                  |
     | d    | 2     | -4    | bstr    | Private key                      |
     +------+-------+-------+---------+----------------------------------+
  */

    const coseStruct = cbor.decodeAllSync(COSEPublicKey)[0]
    const tag = Buffer.from([0x04])
    const x = coseStruct.get(-2)
    const y = coseStruct.get(-3)

    return Buffer.concat([tag, x, y])
  }

  /**
   * Convert binary certificate or public key to an OpenSSL-compatible PEM text format.
   * @param  {Buffer} buffer - Cert or PubKey buffer
   * @return {String}             - PEM
   */
  private ASN1toPEM(pkBuffer: Buffer) {
    let type
    if (pkBuffer.length == 65 && pkBuffer[0] == 0x04) {
      /*
          If needed, we encode rawpublic key to ASN structure, adding metadata:
          SEQUENCE {
            SEQUENCE {
               OBJECTIDENTIFIER 1.2.840.10045.2.1 (ecPublicKey)
               OBJECTIDENTIFIER 1.2.840.10045.3.1.7 (P-256)
            }
            BITSTRING <raw public key>
          }
          Luckily, to do that, we just need to prefix it with constant 26 bytes (metadata is constant).
      */

      pkBuffer = Buffer.concat([
        Buffer.from(
          '3059301306072a8648ce3d020106082a8648ce3d030107034200',
          'hex',
        ),
        pkBuffer,
      ])

      type = 'PUBLIC KEY'
    } else {
      type = 'CERTIFICATE'
    }

    const b64cert = pkBuffer.toString('base64')

    let PEMKey = ''
    for (let i = 0; i < Math.ceil(b64cert.length / 64); i++) {
      const start = 64 * i

      PEMKey += b64cert.substr(start, 64) + '\n'
    }

    PEMKey = `-----BEGIN ${type}-----\n` + PEMKey + `-----END ${type}-----\n`

    return PEMKey
  }

  /**
   * Takes signature, data and PEM public key and tries to verify signature
   * @param  {Buffer} signature
   * @param  {Buffer} data
   * @param  {String} publicKey - PEM encoded public key
   * @return {Boolean}
   */
  private verifySignature(signature, data, publicKey) {
    return crypto
      .createVerify('SHA256')
      .update(data)
      .verify(publicKey, signature)
  }

  verifyAuthenticatorAttestationResponse(webAuthnResponse: ChallengeRequest) {
    const attestationBuffer = base64url.toBuffer(
      webAuthnResponse.response.attestationObject,
    )
    const ctapMakeCredResp = cbor.decodeAllSync(attestationBuffer)[0]

    const response: {
      verified: boolean
      authrInfo?: {
        fmt: string
        publicKey: string
        counter: number
        credID: string
      }
    } = { verified: false }
    if (ctapMakeCredResp.fmt === 'fido-u2f') {
      const authrDataStruct = this.parseMakeCredAuthData(
        ctapMakeCredResp.authData,
      )

      if (!(authrDataStruct.flags & U2F_USER_PRESENTED))
        throw new Error('User was NOT presented durring authentication!')

      const clientDataHash = this.hash(
        base64url.toBuffer(webAuthnResponse.response.clientDataJSON),
      )
      const reservedByte = Buffer.from([0x00])
      const publicKey = this.COSEECDHAtoPKCS(authrDataStruct.COSEPublicKey)
      const signatureBase = Buffer.concat([
        reservedByte,
        authrDataStruct.rpIdHash,
        clientDataHash,
        authrDataStruct.credID,
        publicKey,
      ])

      const PEMCertificate = this.ASN1toPEM(ctapMakeCredResp.attStmt.x5c[0])
      const signature = ctapMakeCredResp.attStmt.sig

      response.verified = this.verifySignature(
        signature,
        signatureBase,
        PEMCertificate,
      )

      if (response.verified) {
        response.authrInfo = {
          fmt: 'fido-u2f',
          publicKey: base64url.encode(publicKey),
          counter: authrDataStruct.counter,
          credID: base64url.encode(authrDataStruct.credID),
        }
      }
    } else if (
      ctapMakeCredResp.fmt === 'packed' &&
      ctapMakeCredResp.attStmt.hasOwnProperty('x5c')
    ) {
      const authrDataStruct = this.parseMakeCredAuthData(
        ctapMakeCredResp.authData,
      )

      if (!(authrDataStruct.flags & U2F_USER_PRESENTED)) {
        throw new Error('User was NOT presented durring authentication!')
      }

      const clientDataHash = this.hash(
        base64url.toBuffer(webAuthnResponse.response.clientDataJSON),
      )
      const publicKey = this.COSEECDHAtoPKCS(authrDataStruct.COSEPublicKey)
      const signatureBase = Buffer.concat([
        ctapMakeCredResp.authData,
        clientDataHash,
      ])

      const PEMCertificate = this.ASN1toPEM(ctapMakeCredResp.attStmt.x5c[0])
      const signature = ctapMakeCredResp.attStmt.sig

      const pem = Certificate.fromPEM(Buffer.from(PEMCertificate))

      // Getting requirements from https://www.w3.org/TR/webauthn/#packed-attestation
      const aaguid_ext = pem.getExtension('1.3.6.1.4.1.45724.1.1.4')

      response.verified = // Verify that sig is a valid signature over the concatenation of authenticatorData
        // and clientDataHash using the attestation public key in attestnCert with the algorithm specified in alg.
        this.verifySignature(signature, signatureBase, PEMCertificate) &&
        // version must be 3 (which is indicated by an ASN.1 INTEGER with value 2)
        pem.version == 3 &&
        // ISO 3166 valid country
        typeof iso_3166_1.whereAlpha2(pem.subject.countryName) !==
          'undefined' &&
        // Legal name of the Authenticator vendor (UTF8String)
        pem.subject.organizationName &&
        // Literal string “Authenticator Attestation” (UTF8String)
        pem.subject.organizationalUnitName === 'Authenticator Attestation' &&
        // A UTF8String of the vendor’s choosing
        pem.subject.commonName &&
        // The Basic Constraints extension MUST have the CA component set to false
        !pem.isCA &&
        // If attestnCert contains an extension with OID 1.3.6.1.4.1.45724.1.1.4 (id-fido-gen-ce-aaguid)
        // verify that the value of this extension matches the aaguid in authenticatorData.
        // The extension MUST NOT be marked as critical.
        (aaguid_ext != null
          ? authrDataStruct.hasOwnProperty('aaguid')
            ? !aaguid_ext.critical &&
              aaguid_ext.value.slice(2).equals(authrDataStruct.aaguid)
            : false
          : true)

      if (response.verified) {
        response.authrInfo = {
          fmt: 'fido-u2f',
          publicKey: base64url.encode(publicKey),
          counter: authrDataStruct.counter,
          credID: base64url.encode(authrDataStruct.credID),
        }
      }
      // check self-signed
    } else if (ctapMakeCredResp.fmt === 'packed') {
      const authrDataStruct = this.parseMakeCredAuthData(
        ctapMakeCredResp.authData,
      )
      if (!(authrDataStruct.flags & U2F_USER_PRESENTED)) {
        throw new Error('User was NOT presented durring authentication!')
      }

      const clientDataHash = this.hash(
        base64url.toBuffer(webAuthnResponse.response.clientDataJSON),
      )
      const publicKey = this.COSEECDHAtoPKCS(authrDataStruct.COSEPublicKey)
      const signatureBase = Buffer.concat([
        ctapMakeCredResp.authData,
        clientDataHash,
      ])
      const PEMCertificate = this.ASN1toPEM(publicKey)
      const {
        attStmt: { sig: signature, alg },
      } = ctapMakeCredResp
      response.verified =
        alg === -7 &&
        this.verifySignature(signature, signatureBase, PEMCertificate)
      if (response.verified) {
        response.authrInfo = {
          fmt: 'fido-u2f',
          publicKey: base64url.encode(publicKey),
          counter: authrDataStruct.counter,
          credID: base64url.encode(authrDataStruct.credID),
        }
      }
    } else {
      console.log(ctapMakeCredResp)
      throw new Error('Unsupported attestation format! ' + ctapMakeCredResp.fmt)
    }

    return response
  }
}
