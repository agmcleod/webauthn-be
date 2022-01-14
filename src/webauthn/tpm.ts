// Logic here is pulled from https://medium.com/webauthnworks/verifying-fido-tpm2-0-attestation-fc7243847498
import { TPM_ECC_CURVE, TPM_ST, TPM_ALG } from './tpm.constants'

export function parseCertInfo(certInfoBuffer: Buffer) {
  const magicBuffer = certInfoBuffer.slice(0, 4)
  const magic = magicBuffer.readUInt32BE(0)
  certInfoBuffer = certInfoBuffer.slice(4)

  const typeBuffer = certInfoBuffer.slice(0, 2)
  const type = TPM_ST[typeBuffer.readUInt16BE(0)]
  certInfoBuffer = certInfoBuffer.slice(2)

  const qualifiedSignerLength = certInfoBuffer.slice(0, 2).readUInt16BE(0)
  certInfoBuffer = certInfoBuffer.slice(2)
  const qualifiedSigner = certInfoBuffer.slice(0, qualifiedSignerLength)
  certInfoBuffer = certInfoBuffer.slice(qualifiedSignerLength)

  const extraDataLength = certInfoBuffer.slice(0, 2).readUInt16BE(0)
  certInfoBuffer = certInfoBuffer.slice(2)
  const extraData = certInfoBuffer.slice(0, extraDataLength)
  certInfoBuffer = certInfoBuffer.slice(extraDataLength)

  const clockInfo = {
    clock: certInfoBuffer.slice(0, 8),
    resetCount: certInfoBuffer.slice(8, 12).readUInt32BE(0),
    restartCount: certInfoBuffer.slice(12, 16).readUInt32BE(0),
    safe: !!certInfoBuffer[16],
  }
  certInfoBuffer = certInfoBuffer.slice(17)

  const firmwareVersion = certInfoBuffer.slice(0, 8)
  certInfoBuffer = certInfoBuffer.slice(8)

  const attestedNameBufferLength = certInfoBuffer.slice(0, 2).readUInt16BE(0)
  const attestedNameBuffer = certInfoBuffer.slice(
    2,
    attestedNameBufferLength + 2,
  )
  certInfoBuffer = certInfoBuffer.slice(2 + attestedNameBufferLength)

  const attestedQualifiedNameBufferLength = certInfoBuffer
    .slice(0, 2)
    .readUInt16BE(0)
  const attestedQualifiedNameBuffer = certInfoBuffer.slice(
    2,
    attestedQualifiedNameBufferLength + 2,
  )
  certInfoBuffer = certInfoBuffer.slice(2 + attestedQualifiedNameBufferLength)

  const attested = {
    nameAlg: TPM_ALG[attestedNameBuffer.slice(0, 2).readUInt16BE(0)],
    name: attestedNameBuffer,
    qualifiedName: attestedQualifiedNameBuffer,
  }

  return {
    magic,
    type,
    qualifiedSigner,
    extraData,
    clockInfo,
    firmwareVersion,
    attested,
  }
}

export function parsePubArea(pubAreaBuffer) {
  const typeBuffer = pubAreaBuffer.slice(0, 2)
  const type = TPM_ALG[typeBuffer.readUInt16BE(0)]
  pubAreaBuffer = pubAreaBuffer.slice(2)

  const nameAlgBuffer = pubAreaBuffer.slice(0, 2)
  const nameAlg = TPM_ALG[nameAlgBuffer.readUInt16BE(0)]
  pubAreaBuffer = pubAreaBuffer.slice(2)

  const objectAttributesBuffer = pubAreaBuffer.slice(0, 4)
  const objectAttributesInt = objectAttributesBuffer.readUInt32BE(0)
  const objectAttributes = {
    fixedTPM: !!(objectAttributesInt & 1),
    stClear: !!(objectAttributesInt & 2),
    fixedParent: !!(objectAttributesInt & 8),
    sensitiveDataOrigin: !!(objectAttributesInt & 16),
    userWithAuth: !!(objectAttributesInt & 32),
    adminWithPolicy: !!(objectAttributesInt & 64),
    noDA: !!(objectAttributesInt & 512),
    encryptedDuplication: !!(objectAttributesInt & 1024),
    restricted: !!(objectAttributesInt & 32768),
    decrypt: !!(objectAttributesInt & 65536),
    signORencrypt: !!(objectAttributesInt & 131072),
  }
  pubAreaBuffer = pubAreaBuffer.slice(4)

  const authPolicyLength = pubAreaBuffer.slice(0, 2).readUInt16BE(0)
  pubAreaBuffer = pubAreaBuffer.slice(2)
  const authPolicy = pubAreaBuffer.slice(0, authPolicyLength)
  pubAreaBuffer = pubAreaBuffer.slice(authPolicyLength)

  let parameters = undefined
  if (type === 'TPM_ALG_RSA') {
    parameters = {
      symmetric: TPM_ALG[pubAreaBuffer.slice(0, 2).readUInt16BE(0)],
      scheme: TPM_ALG[pubAreaBuffer.slice(2, 4).readUInt16BE(0)],
      keyBits: pubAreaBuffer.slice(4, 6).readUInt16BE(0),
      exponent: pubAreaBuffer.slice(6, 10).readUInt32BE(0),
    }
    pubAreaBuffer = pubAreaBuffer.slice(10)
  } else if (type === 'TPM_ALG_ECC') {
    parameters = {
      symmetric: TPM_ALG[pubAreaBuffer.slice(0, 2).readUInt16BE(0)],
      scheme: TPM_ALG[pubAreaBuffer.slice(2, 4).readUInt16BE(0)],
      curveID: TPM_ECC_CURVE[pubAreaBuffer.slice(4, 6).readUInt16BE(0)],
      kdf: TPM_ALG[pubAreaBuffer.slice(6, 8).readUInt16BE(0)],
    }
    pubAreaBuffer = pubAreaBuffer.slice(8)
  } else throw new Error(type + ' is an unsupported type!')

  const uniqueLength = pubAreaBuffer.slice(0, 2).readUInt16BE(0)
  pubAreaBuffer = pubAreaBuffer.slice(2)
  const unique = pubAreaBuffer.slice(0, uniqueLength)
  pubAreaBuffer = pubAreaBuffer.slice(uniqueLength)

  return {
    type,
    nameAlg,
    objectAttributes,
    authPolicy,
    parameters,
    unique,
  }
}
