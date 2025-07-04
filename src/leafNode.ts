import { Capabilities, decodeCapabilities, encodeCapabilities } from "./capabilities"
import { encodeUint32 } from "./codec/number"
import { Decoder, mapDecoders, mapDecoder, flatMapDecoder, succeedDecoder, mapDecoderOption } from "./codec/tlsDecoder"
import { Encoder, contramapEncoders, contramapEncoder } from "./codec/tlsEncoder"
import { encodeVarLenData, decodeVarLenData, encodeVarLenType, decodeVarLenType } from "./codec/variableLength"
import { encodeCredential, decodeCredential, Credential } from "./credential"
import { Signature, signWithLabel, verifyWithLabel } from "./crypto/signature"
import { Extension, encodeExtension, decodeExtension } from "./extension"
import { encodeLeafNodeSource, decodeLeafNodeSource, LeafNodeSourceName } from "./leafNodeSource"
import { Lifetime, encodeLifetime, decodeLifetime } from "./lifetime"

export type LeafNodeData = {
  hpkePublicKey: Uint8Array
  signaturePublicKey: Uint8Array
  credential: Credential
  capabilities: Capabilities
}

export const encodeLeafNodeData: Encoder<LeafNodeData> = contramapEncoders(
  [encodeVarLenData, encodeVarLenData, encodeCredential, encodeCapabilities],
  (data) => [data.hpkePublicKey, data.signaturePublicKey, data.credential, data.capabilities] as const,
)

export const decodeLeafNodeData: Decoder<LeafNodeData> = mapDecoders(
  [decodeVarLenData, decodeVarLenData, decodeCredential, decodeCapabilities],
  (hpkePublicKey, signaturePublicKey, credential, capabilities) => ({
    hpkePublicKey,
    signaturePublicKey,
    credential,
    capabilities,
  }),
)

export type LeafNodeInfo = LeafNodeInfoKeyPackage | LeafNodeInfoUpdate | LeafNodeInfoCommit
export type LeafNodeInfoKeyPackage = { leafNodeSource: "key_package"; lifetime: Lifetime }
export type LeafNodeInfoUpdate = { leafNodeSource: "update" }
export type LeafNodeInfoCommit = { leafNodeSource: "commit"; parentHash: Uint8Array }

export const encodeLeafNodeInfoLifetime: Encoder<LeafNodeInfoKeyPackage> = contramapEncoders(
  [encodeLeafNodeSource, encodeLifetime],
  (info) => ["key_package", info.lifetime] as const,
)

export const encodeLeafNodeInfoUpdate: Encoder<LeafNodeInfoUpdate> = contramapEncoder(
  encodeLeafNodeSource,
  (i) => i.leafNodeSource,
)

export const encodeLeafNodeInfoCommit: Encoder<LeafNodeInfoCommit> = contramapEncoders(
  [encodeLeafNodeSource, encodeVarLenData],
  (info) => ["commit", info.parentHash] as const,
)

export const encodeLeafNodeInfo: Encoder<LeafNodeInfo> = (info) => {
  switch (info.leafNodeSource) {
    case "key_package":
      return encodeLeafNodeInfoLifetime(info)
    case "update":
      return encodeLeafNodeInfoUpdate(info)
    case "commit":
      return encodeLeafNodeInfoCommit(info)
  }
}

export const decodeLeafNodeInfoLifetime: Decoder<LeafNodeInfoKeyPackage> = mapDecoder(decodeLifetime, (lifetime) => ({
  leafNodeSource: "key_package",
  lifetime,
}))

export const decodeLeafNodeInfoCommit: Decoder<LeafNodeInfoCommit> = mapDecoders([decodeVarLenData], (parentHash) => ({
  leafNodeSource: "commit",
  parentHash,
}))

export const decodeLeafNodeInfo: Decoder<LeafNodeInfo> = flatMapDecoder(
  decodeLeafNodeSource,
  (leafNodeSource): Decoder<LeafNodeInfo> => {
    switch (leafNodeSource) {
      case "key_package":
        return decodeLeafNodeInfoLifetime
      case "update":
        return succeedDecoder({ leafNodeSource })
      case "commit":
        return decodeLeafNodeInfoCommit
    }
  },
)

export type LeafNodeExtensions = { extensions: Extension[] }

export const encodeLeafNodeExtensions: Encoder<LeafNodeExtensions> = contramapEncoder(
  encodeVarLenType(encodeExtension),
  (ext) => ext.extensions,
)

export const decodeLeafNodeExtensions: Decoder<LeafNodeExtensions> = mapDecoder(
  decodeVarLenType(decodeExtension),
  (extensions) => ({ extensions }),
)

type GroupIdLeafIndex = {
  leafNodeSource: Exclude<LeafNodeSourceName, "key_package">
  groupId: Uint8Array
  leafIndex: number
}

export const encodeGroupIdLeafIndex: Encoder<GroupIdLeafIndex> = contramapEncoders(
  [encodeVarLenData, encodeUint32],
  (g) => [g.groupId, g.leafIndex] as const,
)

export type LeafNodeGroupInfo = GroupIdLeafIndex | { leafNodeSource: "key_package" }

export const encodeLeafNodeGroupInfo: Encoder<LeafNodeGroupInfo> = (info) => {
  switch (info.leafNodeSource) {
    case "key_package":
      return new Uint8Array()
    case "update":
    case "commit":
      return encodeGroupIdLeafIndex(info)
  }
}

export type LeafNodeTBS = LeafNodeData & LeafNodeInfo & LeafNodeExtensions & { info: LeafNodeGroupInfo }

export type LeafNodeTBSCommit = LeafNodeData & LeafNodeInfoCommit & LeafNodeExtensions & { info: GroupIdLeafIndex }

export type LeafNodeTBSKeyPackage = LeafNodeData &
  LeafNodeInfoKeyPackage &
  LeafNodeExtensions & { info: { leafNodeSource: "key_package" } }

export const encodeLeafNodeTBS: Encoder<LeafNodeTBS> = contramapEncoders(
  [encodeLeafNodeData, encodeLeafNodeInfo, encodeLeafNodeExtensions, encodeLeafNodeGroupInfo],
  (tbs) => [tbs, tbs, tbs, tbs.info] as const,
)

export type LeafNode = LeafNodeData & LeafNodeInfo & LeafNodeExtensions & { signature: Uint8Array }

export const encodeLeafNode: Encoder<LeafNode> = contramapEncoders(
  [encodeLeafNodeData, encodeLeafNodeInfo, encodeLeafNodeExtensions, encodeVarLenData],
  (leafNode) => [leafNode, leafNode, leafNode, leafNode.signature] as const,
)

export const decodeLeafNode: Decoder<LeafNode> = mapDecoders(
  [decodeLeafNodeData, decodeLeafNodeInfo, decodeLeafNodeExtensions, decodeVarLenData],
  (data, info, extensions, signature) => ({
    ...data,
    ...info,
    ...extensions,
    signature,
  }),
)

export type LeafNodeKeyPackage = LeafNode & LeafNodeInfoKeyPackage

export const decodeLeafNodeKeyPackage: Decoder<LeafNodeKeyPackage> = mapDecoderOption(decodeLeafNode, (ln) =>
  ln.leafNodeSource === "key_package" ? ln : undefined,
)

export type LeafNodeCommit = LeafNode & LeafNodeInfoCommit

export const decodeLeafNodeCommit: Decoder<LeafNodeCommit> = mapDecoderOption(decodeLeafNode, (ln) =>
  ln.leafNodeSource === "commit" ? ln : undefined,
)

export type LeafNodeUpdate = LeafNode & LeafNodeInfoUpdate

export const decodeLeafNodeUpdate: Decoder<LeafNodeUpdate> = mapDecoderOption(decodeLeafNode, (ln) =>
  ln.leafNodeSource === "update" ? ln : undefined,
)

function toTbs(leafNode: LeafNode, groupId: Uint8Array, leafIndex: number): LeafNodeTBS {
  return { ...leafNode, info: { leafNodeSource: leafNode.leafNodeSource, groupId, leafIndex } }
}

export async function signLeafNodeCommit(
  tbs: LeafNodeTBSCommit,
  signaturePrivateKey: Uint8Array,
  sig: Signature,
): Promise<LeafNodeCommit> {
  return { ...tbs, signature: await signWithLabel(signaturePrivateKey, "LeafNodeTBS", encodeLeafNodeTBS(tbs), sig) }
}

export async function signLeafNodeKeyPackage(
  tbs: LeafNodeTBSKeyPackage,
  signaturePrivateKey: Uint8Array,
  sig: Signature,
): Promise<LeafNodeKeyPackage> {
  return { ...tbs, signature: await signWithLabel(signaturePrivateKey, "LeafNodeTBS", encodeLeafNodeTBS(tbs), sig) }
}

export function verifyLeafNodeSignature(
  leaf: LeafNode,
  groupId: Uint8Array,
  leafIndex: number,
  sig: Signature,
): Promise<boolean> {
  return verifyWithLabel(
    leaf.signaturePublicKey,
    "LeafNodeTBS",
    encodeLeafNodeTBS(toTbs(leaf, groupId, leafIndex)),
    leaf.signature,
    sig,
  )
}

export function verifyLeafNodeSignatureKeyPackage(leaf: LeafNodeKeyPackage, sig: Signature): Promise<boolean> {
  return verifyWithLabel(
    leaf.signaturePublicKey,
    "LeafNodeTBS",
    encodeLeafNodeTBS({ ...leaf, info: { leafNodeSource: leaf.leafNodeSource } }),
    leaf.signature,
    sig,
  )
}
