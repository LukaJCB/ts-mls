import { Decoder, flatMapDecoder, mapDecoder, mapDecoders } from "./codec/tlsDecoder.js"
import { contramapBufferEncoders, Encoder } from "./codec/tlsEncoder.js"
import { groupInfoDecoder, groupInfoEncoder, GroupInfo } from "./groupInfo.js"
import { keyPackageDecoder, keyPackageEncoder, KeyPackage } from "./keyPackage.js"
import { privateMessageDecoder, privateMessageEncoder, PrivateMessage } from "./privateMessage.js"
import { protocolVersionDecoder, protocolVersionEncoder, ProtocolVersionValue } from "./protocolVersion.js"
import { publicMessageDecoder, publicMessageEncoder, PublicMessage } from "./publicMessage.js"
import { welcomeDecoder, Welcome, welcomeEncoder } from "./welcome.js"
import { wireformatDecoder, wireformatEncoder, wireformats } from "./wireformat.js"

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
export type MlsFramedMessage = MlsMessageProtocol & (MlsPrivateMessage | MlsPublicMessage)

/** @public */
export type MlsWelcomeMessage = MlsMessageProtocol & MlsWelcome

/** @public */
export type MlsMessageContent = MlsWelcome | MlsPrivateMessage | MlsGroupInfo | MlsKeyPackage | MlsPublicMessage

/** @public */
export type MlsMessage = MlsMessageProtocol & MlsMessageContent

export const mlsPublicMessageEncoder: Encoder<MlsPublicMessage> = contramapBufferEncoders(
  [wireformatEncoder, publicMessageEncoder],
  (msg) => [msg.wireformat, msg.publicMessage] as const,
)

export const mlsWelcomeEncoder: Encoder<MlsWelcome> = contramapBufferEncoders(
  [wireformatEncoder, welcomeEncoder],
  (wm) => [wm.wireformat, wm.welcome] as const,
)

export const mlsPrivateMessageEncoder: Encoder<MlsPrivateMessage> = contramapBufferEncoders(
  [wireformatEncoder, privateMessageEncoder],
  (pm) => [pm.wireformat, pm.privateMessage] as const,
)

export const mlsGroupInfoEncoder: Encoder<MlsGroupInfo> = contramapBufferEncoders(
  [wireformatEncoder, groupInfoEncoder],
  (gi) => [gi.wireformat, gi.groupInfo] as const,
)

export const mlsKeyPackageEncoder: Encoder<MlsKeyPackage> = contramapBufferEncoders(
  [wireformatEncoder, keyPackageEncoder],
  (kp) => [kp.wireformat, kp.keyPackage] as const,
)

export const mlsMessageContentEncoder: Encoder<MlsMessageContent> = (mc) => {
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

export const mlsMessageContentDecoder: Decoder<MlsMessageContent> = flatMapDecoder(
  wireformatDecoder,
  (wireformat): Decoder<MlsMessageContent> => {
    switch (wireformat) {
      case wireformats.mls_public_message:
        return mapDecoder(publicMessageDecoder, (publicMessage) => ({ wireformat, publicMessage }))
      case wireformats.mls_welcome:
        return mapDecoder(welcomeDecoder, (welcome) => ({ wireformat, welcome }))
      case wireformats.mls_private_message:
        return mapDecoder(privateMessageDecoder, (privateMessage) => ({ wireformat, privateMessage }))
      case wireformats.mls_group_info:
        return mapDecoder(groupInfoDecoder, (groupInfo) => ({ wireformat, groupInfo }))
      case wireformats.mls_key_package:
        return mapDecoder(keyPackageDecoder, (keyPackage) => ({ wireformat, keyPackage }))
    }
  },
)

/** @public */
export const mlsMessageEncoder: Encoder<MlsMessage> = contramapBufferEncoders(
  [protocolVersionEncoder, mlsMessageContentEncoder],
  (w) => [w.version, w] as const,
)

/** @public */
export const mlsMessageDecoder: Decoder<MlsMessage> = mapDecoders(
  [protocolVersionDecoder, mlsMessageContentDecoder],
  (version, mc) => ({ ...mc, version }),
)
