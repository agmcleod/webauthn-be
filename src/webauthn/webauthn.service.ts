import { Injectable } from '@nestjs/common'
import base64url from 'base64url'
import * as cbor from 'cbor'
import * as crypto from 'crypto'
import { Certificate } from '@fidm/x509'
import iso_3166_1 from 'iso-3166-1'

import { ChallengeRequest } from './dtos/challenge-request.dto'
import { parseCertInfo, parsePubArea } from './tpm'

const U2F_USER_PRESENTED = 0x01
const U2F_USER_VERIFIED = 0b010
// values retrieved from: https://www.trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf
const TPM_GENERATED_VALUE = 0xff544347
const TPM_ST_ATTEST_CERTIFY = 0x8017

type AttestationResponse = {
  verified: boolean
  authrInfo?: {
    fmt: string
    publicKey: string
    counter: number
    credID: string
  }
}

// Code in this class referenced from: https://github.com/fido-alliance/webauthn-demo/blob/master/utils.js
// As well as referencing the spec: https://w3c.github.io/webauthn/#sctn-registering-a-new-credential

// TODO: Check into https://github.com/webauthn-open-source/fido2-lib

@Injectable()
export class WebauthnService {
  /**
   * Parses authenticatorData buffer.
   * @param  {Buffer} buffer - authenticatorData buffer
   * @return {Object}        - parsed authenticatorData struct
   */
  private parseMakeCredAuthData(buffer) {
    // these byte ranges are based on https://w3c.github.io/webauthn/images/fido-attestation-structures.svg
    // which is the packed attestation format
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
    // the variable length of the credential ID
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
   * TODO: Expand to support other algorithm types. https://www.iana.org/assignments/cose/cose.xhtml, COSE algorithms section
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

  verifyAuthenticatorAttestationResponse(
    webAuthnResponse: ChallengeRequest,
  ): AttestationResponse {
    const attestationBuffer = base64url.toBuffer(
      webAuthnResponse.response.attestationObject,
    )
    const ctapMakeCredResp = cbor.decodeAllSync(attestationBuffer)[0]

    const authrDataStruct = this.parseMakeCredAuthData(
      ctapMakeCredResp.authData,
    )

    // 7.2 step 20, allow none set for the attestation format
    if (
      ctapMakeCredResp.fmt === 'none' &&
      (!ctapMakeCredResp.attStmt ||
        Object.keys(ctapMakeCredResp.attStmt).length === 0)
    ) {
      return {
        verified: true,
      }
    }

    // instead of localhost, use the TLD or first level sub domain: https://w3c.github.io/webauthn/#rp-id
    // 7.2 step 12
    if (!this.hash('localhost').equals(authrDataStruct.rpIdHash)) {
      throw new Error('relaying party id did not match')
    }

    // 7.2 step 13
    if (!(authrDataStruct.flags & U2F_USER_PRESENTED)) {
      throw new Error('User was NOT presented durring authentication!')
    }

    // 7.2 step 21
    if (authrDataStruct.credID.length > 1023) {
      throw new Error('Credential ID is larger than 1023 bytes')
    }

    // TODO step 22, check uniqueness of credential ID. Could reinforce this in challenge retrieval too,
    // which is where the id is generated by this app

    // 7.3 user verfied. This is an optional step, but additional to distinguish individual users if need be.
    // https://w3c.github.io/webauthn/#user-verification
    const verifyUser = false
    if (verifyUser && !(authrDataStruct.flags & U2F_USER_VERIFIED)) {
      throw new Error('User was NOT verified!')
    }

    const response: AttestationResponse = { verified: false }
    if (ctapMakeCredResp.fmt === 'fido-u2f') {
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
          fmt: ctapMakeCredResp.fmt,
          publicKey: base64url.encode(publicKey),
          counter: authrDataStruct.counter,
          credID: base64url.encode(authrDataStruct.credID),
        }
      }
    } else if (
      ctapMakeCredResp.fmt === 'packed' &&
      ctapMakeCredResp.attStmt.hasOwnProperty('x5c')
    ) {
      // https://w3c.github.io/webauthn/#sctn-packed-attestation-cert-requirements
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

      // Link provided above specifies the extension used here
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
          fmt: ctapMakeCredResp.fmt,
          publicKey: base64url.encode(publicKey),
          counter: authrDataStruct.counter,
          credID: base64url.encode(authrDataStruct.credID),
        }
      }
      // check self-signed
    } else if (ctapMakeCredResp.fmt === 'packed') {
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
          fmt: ctapMakeCredResp.fmt,
          publicKey: base64url.encode(publicKey),
          counter: authrDataStruct.counter,
          credID: base64url.encode(authrDataStruct.credID),
        }
      }
    } else if (ctapMakeCredResp.fmt === 'tpm') {
      const attStmt = ctapMakeCredResp.attStmt
      if (!attStmt.pubArea) {
        throw new Error('TPM attestation missing certInfo')
      }
      if (!attStmt.certInfo) {
        throw new Error('TPM attestation missing pubArea')
      }
      const clientDataHash = this.hash(
        base64url.toBuffer(webAuthnResponse.response.clientDataJSON),
      )
      const attToBeSigned = Buffer.concat([
        ctapMakeCredResp.authData,
        clientDataHash,
      ])

      const certInfo = parseCertInfo(attStmt.certInfo)
      const pubArea = parsePubArea(attStmt.pubArea)

      response.verified =
        attStmt.ver === '2.0' &&
        certInfo.magic === TPM_GENERATED_VALUE &&
        certInfo.type === TPM_ST_ATTEST_CERTIFY
    } else if (ctapMakeCredResp.fmt === 'android-safetynet') {
      let [header, payload, signature] = ctapMakeCredResp.attStmt.response
        .toString('utf8')
        .split('.')
      const signatureBase = Buffer.from([header, payload].join('.'))

      header = JSON.parse(base64url.decode(header))
      payload = JSON.parse(base64url.decode(payload))
      signature = base64url.toBuffer(signature)

      const PEMCertificate = this.ASN1toPEM(
        Buffer.from(header.x5c[0], 'base64'),
      )

      const pem = Certificate.fromPEM(Buffer.from(PEMCertificate))

      response.verified = // Verify that sig is a valid signature over the concatenation of authenticatorData
        // and clientDataHash using the attestation public key in attestnCert with the algorithm specified in alg.
        this.verifySignature(signature, signatureBase, PEMCertificate) &&
        // version must be 3 (which is indicated by an ASN.1 INTEGER with value 2)
        pem.version == 3 &&
        pem.subject.commonName === 'attest.android.com'
    } else {
      console.error(ctapMakeCredResp)
      throw new Error('Unsupported attestation format! ' + ctapMakeCredResp.fmt)
    }

    return response
  }
}
