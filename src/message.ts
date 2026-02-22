import { Decoder, flatMapDecoder, mapDecoder } from "./codec/tlsDecoder.js"
import { contramapBufferEncoders, Encoder } from "./codec/tlsEncoder.js"
import { groupInfoDecoder, groupInfoEncoder, GroupInfo } from "./groupInfo.js"
import { keyPackageDecoder, keyPackageEncoder, KeyPackage } from "./keyPackage.js"
import { privateMessageDecoder, privateMessageEncoder, PrivateMessage } from "./privateMessage.js"
import { protocolVersionDecoder, protocolVersionEncoder, ProtocolVersionValue } from "./protocolVersion.js"
import { publicMessageDecoder, publicMessageEncoder, PublicMessage } from "./publicMessage.js"
import { welcomeDecoder, Welcome, welcomeEncoder } from "./welcome.js"
import { wireformatDecoder, wireformatEncoder, wireformats } from "./wireformat.js"

/** @public */
export interface MlsWelcomeMessage {
  wireformat: typeof wireformats.mls_welcome
  welcome: Welcome
  version: ProtocolVersionValue
}

/** @public */
export interface MlsPrivateMessage {
  wireformat: typeof wireformats.mls_private_message
  privateMessage: PrivateMessage
  version: ProtocolVersionValue
}

/** @public */
export interface MlsGroupInfo {
  wireformat: typeof wireformats.mls_group_info
  groupInfo: GroupInfo
  version: ProtocolVersionValue
}

/** @public */
export interface MlsKeyPackage {
  wireformat: typeof wireformats.mls_key_package
  keyPackage: KeyPackage
  version: ProtocolVersionValue
}
/** @public */
export interface MlsPublicMessage {
  wireformat: typeof wireformats.mls_public_message
  publicMessage: PublicMessage
  version: ProtocolVersionValue
}

/** @public */
export type MlsFramedMessage = MlsPrivateMessage | MlsPublicMessage

/** @public */
export type MlsMessage = MlsWelcomeMessage | MlsPrivateMessage | MlsGroupInfo | MlsKeyPackage | MlsPublicMessage

const mlsPublicMessageEncoder: Encoder<MlsPublicMessage> = contramapBufferEncoders(
  [protocolVersionEncoder, wireformatEncoder, publicMessageEncoder],
  (msg) => [msg.version, msg.wireformat, msg.publicMessage] as const,
)

const mlsWelcomeEncoder: Encoder<MlsWelcomeMessage> = contramapBufferEncoders(
  [protocolVersionEncoder, wireformatEncoder, welcomeEncoder],
  (wm) => [wm.version, wm.wireformat, wm.welcome] as const,
)

const mlsPrivateMessageEncoder: Encoder<MlsPrivateMessage> = contramapBufferEncoders(
  [protocolVersionEncoder, wireformatEncoder, privateMessageEncoder],
  (pm) => [pm.version, pm.wireformat, pm.privateMessage] as const,
)

const mlsGroupInfoEncoder: Encoder<MlsGroupInfo> = contramapBufferEncoders(
  [protocolVersionEncoder, wireformatEncoder, groupInfoEncoder],
  (gi) => [gi.version, gi.wireformat, gi.groupInfo] as const,
)

const mlsKeyPackageEncoder: Encoder<MlsKeyPackage> = contramapBufferEncoders(
  [protocolVersionEncoder, wireformatEncoder, keyPackageEncoder],
  (kp) => [kp.version, kp.wireformat, kp.keyPackage] as const,
)
/** @public */
export const mlsMessageEncoder: Encoder<MlsMessage> = (mc) => {
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
/** @public */
export const mlsMessageDecoder: Decoder<MlsMessage> = flatMapDecoder(protocolVersionDecoder, (version) =>
  flatMapDecoder(wireformatDecoder, (wireformat): Decoder<MlsMessage> => {
    switch (wireformat) {
      case wireformats.mls_public_message:
        return mapDecoder(publicMessageDecoder, (publicMessage) => ({ version, wireformat, publicMessage }))
      case wireformats.mls_welcome:
        return mapDecoder(welcomeDecoder, (welcome) => ({ version, wireformat, welcome }))
      case wireformats.mls_private_message:
        return mapDecoder(privateMessageDecoder, (privateMessage) => ({ version, wireformat, privateMessage }))
      case wireformats.mls_group_info:
        return mapDecoder(groupInfoDecoder, (groupInfo) => ({ version, wireformat, groupInfo }))
      case wireformats.mls_key_package:
        return mapDecoder(keyPackageDecoder, (keyPackage) => ({ version, wireformat, keyPackage }))
    }
  }),
)
