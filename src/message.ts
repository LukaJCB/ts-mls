import { Decoder, flatMapDecoder, mapDecoder, mapDecoders } from "./codec/tlsDecoder.js"
import { contramapBufferEncoders, BufferEncoder, encode, Encoder } from "./codec/tlsEncoder.js"
import { decodeGroupInfo, groupInfoEncoder, GroupInfo } from "./groupInfo.js"
import { decodeKeyPackage, keyPackageEncoder, KeyPackage } from "./keyPackage.js"
import { decodePrivateMessage, privateMessageEncoder, PrivateMessage } from "./privateMessage.js"
import { decodeProtocolVersion, protocolVersionEncoder, ProtocolVersionValue } from "./protocolVersion.js"
import { decodePublicMessage, publicMessageEncoder, PublicMessage } from "./publicMessage.js"
import { decodeWelcome, Welcome, welcomeEncoder } from "./welcome.js"
import { decodeWireformat, wireformatEncoder, wireformats } from "./wireformat.js"

/** @public */
export interface MlsMessageProtocol {
  version: ProtocolVersionValue
}

/** @public */
export interface MlsWelcome {
  wireformat: typeof wireformats.mls_welcome
  welcome: Welcome
}

/** @public */
export interface MlsPrivateMessage {
  wireformat: typeof wireformats.mls_private_message
  privateMessage: PrivateMessage
}

/** @public */
export interface MlsGroupInfo {
  wireformat: typeof wireformats.mls_group_info
  groupInfo: GroupInfo
}

/** @public */
export interface MlsKeyPackage {
  wireformat: typeof wireformats.mls_key_package
  keyPackage: KeyPackage
}
/** @public */
export interface MlsPublicMessage {
  wireformat: typeof wireformats.mls_public_message
  publicMessage: PublicMessage
}

/** @public */
export type MlsMessageContent = MlsWelcome | MlsPrivateMessage | MlsGroupInfo | MlsKeyPackage | MlsPublicMessage
/** @public */
export type MLSMessage = MlsMessageProtocol & MlsMessageContent

export const mlsPublicMessageEncoder: BufferEncoder<MlsPublicMessage> = contramapBufferEncoders(
  [wireformatEncoder, publicMessageEncoder],
  (msg) => [msg.wireformat, msg.publicMessage] as const,
)

export const encodeMlsPublicMessage: Encoder<MlsPublicMessage> = encode(mlsPublicMessageEncoder)

export const mlsWelcomeEncoder: BufferEncoder<MlsWelcome> = contramapBufferEncoders(
  [wireformatEncoder, welcomeEncoder],
  (wm) => [wm.wireformat, wm.welcome] as const,
)

export const encodeMlsWelcome: Encoder<MlsWelcome> = encode(mlsWelcomeEncoder)

export const mlsPrivateMessageEncoder: BufferEncoder<MlsPrivateMessage> = contramapBufferEncoders(
  [wireformatEncoder, privateMessageEncoder],
  (pm) => [pm.wireformat, pm.privateMessage] as const,
)

export const encodeMlsPrivateMessage: Encoder<MlsPrivateMessage> = encode(mlsPrivateMessageEncoder)

export const mlsGroupInfoEncoder: BufferEncoder<MlsGroupInfo> = contramapBufferEncoders(
  [wireformatEncoder, groupInfoEncoder],
  (gi) => [gi.wireformat, gi.groupInfo] as const,
)

export const encodeMlsGroupInfo: Encoder<MlsGroupInfo> = encode(mlsGroupInfoEncoder)

export const mlsKeyPackageEncoder: BufferEncoder<MlsKeyPackage> = contramapBufferEncoders(
  [wireformatEncoder, keyPackageEncoder],
  (kp) => [kp.wireformat, kp.keyPackage] as const,
)

export const encodeMlsKeyPackage: Encoder<MlsKeyPackage> = encode(mlsKeyPackageEncoder)

export const mlsMessageContentEncoder: BufferEncoder<MlsMessageContent> = (mc) => {
  switch (mc.wireformat) {
    case wireformats.mls_public_message:
      return mlsPublicMessageEncoder(mc)
    case wireformats.mls_welcome:
      return mlsWelcomeEncoder(mc)
    case wireformats.mls_private_message:
      return mlsPrivateMessageEncoder(mc)
    case wireformats.mls_group_info:
      return mlsGroupInfoEncoder(mc)
    case wireformats.mls_key_package:
      return mlsKeyPackageEncoder(mc)
  }
}

export const encodeMlsMessageContent: Encoder<MlsMessageContent> = encode(mlsMessageContentEncoder)

export const decodeMlsMessageContent: Decoder<MlsMessageContent> = flatMapDecoder(
  decodeWireformat,
  (wireformat): Decoder<MlsMessageContent> => {
    switch (wireformat) {
      case wireformats.mls_public_message:
        return mapDecoder(decodePublicMessage, (publicMessage) => ({ wireformat, publicMessage }))
      case wireformats.mls_welcome:
        return mapDecoder(decodeWelcome, (welcome) => ({ wireformat, welcome }))
      case wireformats.mls_private_message:
        return mapDecoder(decodePrivateMessage, (privateMessage) => ({ wireformat, privateMessage }))
      case wireformats.mls_group_info:
        return mapDecoder(decodeGroupInfo, (groupInfo) => ({ wireformat, groupInfo }))
      case wireformats.mls_key_package:
        return mapDecoder(decodeKeyPackage, (keyPackage) => ({ wireformat, keyPackage }))
    }
  },
)

export const mlsMessageEncoder: BufferEncoder<MLSMessage> = contramapBufferEncoders(
  [protocolVersionEncoder, mlsMessageContentEncoder],
  (w) => [w.version, w] as const,
)

/** @public */
export const encodeMlsMessage: Encoder<MLSMessage> = encode(mlsMessageEncoder)

/** @public */
export const decodeMlsMessage: Decoder<MLSMessage> = mapDecoders(
  [decodeProtocolVersion, decodeMlsMessageContent],
  (version, mc) => ({ ...mc, version }),
)
