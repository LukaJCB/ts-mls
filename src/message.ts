import { Decoder, flatMapDecoder, mapDecoder, mapDecoders } from "./codec/tlsDecoder"
import { contramapEncoders, Encoder } from "./codec/tlsEncoder"
import { decodeGroupInfo, encodeGroupInfo, GroupInfo } from "./groupInfo"
import { decodeKeyPackage, encodeKeyPackage, KeyPackage } from "./keyPackage"
import { decodePrivateMessage, encodePrivateMessage, PrivateMessage } from "./privateMessage"
import { decodeProtocolVersion, encodeProtocolVersion, ProtocolVersionName } from "./protocolVersion"
import { decodePublicMessage, encodePublicMessage, PublicMessage } from "./publicMessage"
import { decodeWelcome, encodeWelcome, Welcome } from "./welcome"
import { decodeWireformat, encodeWireformat } from "./wireformat"

export interface MlsMessageProtocol {
  version: ProtocolVersionName
}

export interface MlsWelcome {
  wireformat: "mls_welcome"
  welcome: Welcome
}
export interface MlsPrivateMessage {
  wireformat: "mls_private_message"
  privateMessage: PrivateMessage
}
export interface MlsGroupInfo {
  wireformat: "mls_group_info"
  groupInfo: GroupInfo
}
export interface MlsKeyPackage {
  wireformat: "mls_key_package"
  keyPackage: KeyPackage
}
export interface MlsPublicMessage {
  wireformat: "mls_public_message"
  publicMessage: PublicMessage
}

export type MlsMessageContent = MlsWelcome | MlsPrivateMessage | MlsGroupInfo | MlsKeyPackage | MlsPublicMessage
export type MLSMessage = MlsMessageProtocol & MlsMessageContent

export const encodeMlsMessageContent: Encoder<MlsMessageContent> = (mc) => {
  switch (mc.wireformat) {
    case "mls_public_message":
      return encodeMlsPublicMessage(mc)
    case "mls_welcome":
      return encodeMlsWelcome(mc)
    case "mls_private_message":
      return encodeMlsPrivateMessage(mc)
    case "mls_group_info":
      return encodeMlsGroupInfo(mc)
    case "mls_key_package":
      return encodeMlsKeyPackage(mc)
  }
}

export const encodeMlsPublicMessage: Encoder<MlsPublicMessage> = contramapEncoders(
  [encodeWireformat, encodePublicMessage],
  (msg) => [msg.wireformat, msg.publicMessage] as const,
)

export const encodeMlsWelcome: Encoder<MlsWelcome> = contramapEncoders(
  [encodeWireformat, encodeWelcome],
  (wm) => [wm.wireformat, wm.welcome] as const,
)

export const encodeMlsPrivateMessage: Encoder<MlsPrivateMessage> = contramapEncoders(
  [encodeWireformat, encodePrivateMessage],
  (pm) => [pm.wireformat, pm.privateMessage] as const,
)

export const encodeMlsGroupInfo: Encoder<MlsGroupInfo> = contramapEncoders(
  [encodeWireformat, encodeGroupInfo],
  (gi) => [gi.wireformat, gi.groupInfo] as const,
)

export const encodeMlsKeyPackage: Encoder<MlsKeyPackage> = contramapEncoders(
  [encodeWireformat, encodeKeyPackage],
  (kp) => [kp.wireformat, kp.keyPackage] as const,
)

export const decodeMlsMessageContent: Decoder<MlsMessageContent> = flatMapDecoder(
  decodeWireformat,
  (wireformat): Decoder<MlsMessageContent> => {
    switch (wireformat) {
      case "mls_public_message":
        return mapDecoder(decodePublicMessage, (publicMessage) => ({ wireformat, publicMessage }))
      case "mls_welcome":
        return mapDecoder(decodeWelcome, (welcome) => ({ wireformat, welcome }))
      case "mls_private_message":
        return mapDecoder(decodePrivateMessage, (privateMessage) => ({ wireformat, privateMessage }))
      case "mls_group_info":
        return mapDecoder(decodeGroupInfo, (groupInfo) => ({ wireformat, groupInfo }))
      case "mls_key_package":
        return mapDecoder(decodeKeyPackage, (keyPackage) => ({ wireformat, keyPackage }))
    }
  },
)

export const encodeMlsMessage: Encoder<MLSMessage> = contramapEncoders(
  [encodeProtocolVersion, encodeMlsMessageContent],
  (w) => [w.version, w] as const,
)

export const decodeMlsMessage: Decoder<MLSMessage> = mapDecoders(
  [decodeProtocolVersion, decodeMlsMessageContent],
  (version, mc) => ({ ...mc, version }),
)
