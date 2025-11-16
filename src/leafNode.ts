import { Capabilities, capabilitiesEncoder, decodeCapabilities } from "./capabilities.js"
import { uint32Encoder } from "./codec/number.js"
import {
  Decoder,
  mapDecoders,
  mapDecoder,
  flatMapDecoder,
  succeedDecoder,
  mapDecoderOption,
} from "./codec/tlsDecoder.js"
import {
  BufferEncoder,
  contramapBufferEncoders,
  contramapBufferEncoder,
  encode,
  Encoder,
  encVoid,
} from "./codec/tlsEncoder.js"
import { varLenDataEncoder, decodeVarLenData, varLenTypeEncoder, decodeVarLenType } from "./codec/variableLength.js"
import { credentialEncoder, decodeCredential, Credential } from "./credential.js"
import { Signature, signWithLabel, verifyWithLabel } from "./crypto/signature.js"
import { Extension, extensionEncoder, decodeExtension } from "./extension.js"
import { leafNodeSourceEncoder, decodeLeafNodeSource, LeafNodeSourceName } from "./leafNodeSource.js"
import { Lifetime, lifetimeEncoder, decodeLifetime } from "./lifetime.js"

export interface LeafNodeData {
  hpkePublicKey: Uint8Array
  signaturePublicKey: Uint8Array
  credential: Credential
  capabilities: Capabilities
}

export const leafNodeDataEncoder: BufferEncoder<LeafNodeData> = contramapBufferEncoders(
  [varLenDataEncoder, varLenDataEncoder, credentialEncoder, capabilitiesEncoder],
  (data) => [data.hpkePublicKey, data.signaturePublicKey, data.credential, data.capabilities] as const,
)

export const encodeLeafNodeData: Encoder<LeafNodeData> = encode(leafNodeDataEncoder)

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
export interface LeafNodeInfoKeyPackage {
  leafNodeSource: "key_package"
  lifetime: Lifetime
}
export interface LeafNodeInfoUpdate {
  leafNodeSource: "update"
}
export interface LeafNodeInfoCommit {
  leafNodeSource: "commit"
  parentHash: Uint8Array
}

export const leafNodeInfoLifetimeEncoder: BufferEncoder<LeafNodeInfoKeyPackage> = contramapBufferEncoders(
  [leafNodeSourceEncoder, lifetimeEncoder],
  (info) => ["key_package", info.lifetime] as const,
)

export const encodeLeafNodeInfoLifetime: Encoder<LeafNodeInfoKeyPackage> = encode(leafNodeInfoLifetimeEncoder)

export const leafNodeInfoUpdateEncoder: BufferEncoder<LeafNodeInfoUpdate> = contramapBufferEncoder(
  leafNodeSourceEncoder,
  (i) => i.leafNodeSource,
)

export const encodeLeafNodeInfoUpdate: Encoder<LeafNodeInfoUpdate> = encode(leafNodeInfoUpdateEncoder)

export const leafNodeInfoCommitEncoder: BufferEncoder<LeafNodeInfoCommit> = contramapBufferEncoders(
  [leafNodeSourceEncoder, varLenDataEncoder],
  (info) => ["commit", info.parentHash] as const,
)

export const encodeLeafNodeInfoCommit: Encoder<LeafNodeInfoCommit> = encode(leafNodeInfoCommitEncoder)

export const leafNodeInfoEncoder: BufferEncoder<LeafNodeInfo> = (info) => {
  switch (info.leafNodeSource) {
    case "key_package":
      return leafNodeInfoLifetimeEncoder(info)
    case "update":
      return leafNodeInfoUpdateEncoder(info)
    case "commit":
      return leafNodeInfoCommitEncoder(info)
  }
}

export const encodeLeafNodeInfo: Encoder<LeafNodeInfo> = encode(leafNodeInfoEncoder)

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

export interface LeafNodeExtensions {
  extensions: Extension[]
}

export const leafNodeExtensionsEncoder: BufferEncoder<LeafNodeExtensions> = contramapBufferEncoder(
  varLenTypeEncoder(extensionEncoder),
  (ext) => ext.extensions,
)

export const encodeLeafNodeExtensions: Encoder<LeafNodeExtensions> = encode(leafNodeExtensionsEncoder)

export const decodeLeafNodeExtensions: Decoder<LeafNodeExtensions> = mapDecoder(
  decodeVarLenType(decodeExtension),
  (extensions) => ({ extensions }),
)

type GroupIdLeafIndex = {
  leafNodeSource: Exclude<LeafNodeSourceName, "key_package">
  groupId: Uint8Array
  leafIndex: number
}

export const groupIdLeafIndexEncoder: BufferEncoder<GroupIdLeafIndex> = contramapBufferEncoders(
  [varLenDataEncoder, uint32Encoder],
  (g) => [g.groupId, g.leafIndex] as const,
)

export const encodeGroupIdLeafIndex: Encoder<GroupIdLeafIndex> = encode(groupIdLeafIndexEncoder)

export type LeafNodeGroupInfo = GroupIdLeafIndex | { leafNodeSource: "key_package" }

export const leafNodeGroupInfoEncoder: BufferEncoder<LeafNodeGroupInfo> = (info) => {
  switch (info.leafNodeSource) {
    case "key_package":
      return encVoid
    case "update":
    case "commit":
      return groupIdLeafIndexEncoder(info)
  }
}

export const encodeLeafNodeGroupInfo: Encoder<LeafNodeGroupInfo> = encode(leafNodeGroupInfoEncoder)

export type LeafNodeTBS = LeafNodeData & LeafNodeInfo & LeafNodeExtensions & { info: LeafNodeGroupInfo }

export type LeafNodeTBSCommit = LeafNodeData & LeafNodeInfoCommit & LeafNodeExtensions & { info: GroupIdLeafIndex }

export type LeafNodeTBSKeyPackage = LeafNodeData &
  LeafNodeInfoKeyPackage &
  LeafNodeExtensions & { info: { leafNodeSource: "key_package" } }

export const leafNodeTBSEncoder: BufferEncoder<LeafNodeTBS> = contramapBufferEncoders(
  [leafNodeDataEncoder, leafNodeInfoEncoder, leafNodeExtensionsEncoder, leafNodeGroupInfoEncoder],
  (tbs) => [tbs, tbs, tbs, tbs.info] as const,
)

export const encodeLeafNodeTBS: Encoder<LeafNodeTBS> = encode(leafNodeTBSEncoder)

export type LeafNode = LeafNodeData & LeafNodeInfo & LeafNodeExtensions & { signature: Uint8Array }

export const leafNodeEncoder: BufferEncoder<LeafNode> = contramapBufferEncoders(
  [leafNodeDataEncoder, leafNodeInfoEncoder, leafNodeExtensionsEncoder, varLenDataEncoder],
  (leafNode) => [leafNode, leafNode, leafNode, leafNode.signature] as const,
)

export const encodeLeafNode: Encoder<LeafNode> = encode(leafNodeEncoder)

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
  return {
    ...tbs,
    signature: await signWithLabel(signaturePrivateKey, "LeafNodeTBS", encode(leafNodeTBSEncoder)(tbs), sig),
  }
}

export async function signLeafNodeKeyPackage(
  tbs: LeafNodeTBSKeyPackage,
  signaturePrivateKey: Uint8Array,
  sig: Signature,
): Promise<LeafNodeKeyPackage> {
  return {
    ...tbs,
    signature: await signWithLabel(signaturePrivateKey, "LeafNodeTBS", encode(leafNodeTBSEncoder)(tbs), sig),
  }
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
    encode(leafNodeTBSEncoder)(toTbs(leaf, groupId, leafIndex)),
    leaf.signature,
    sig,
  )
}

export function verifyLeafNodeSignatureKeyPackage(leaf: LeafNodeKeyPackage, sig: Signature): Promise<boolean> {
  return verifyWithLabel(
    leaf.signaturePublicKey,
    "LeafNodeTBS",
    encode(leafNodeTBSEncoder)({ ...leaf, info: { leafNodeSource: leaf.leafNodeSource } }),
    leaf.signature,
    sig,
  )
}
