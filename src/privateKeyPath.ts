import { uint32Decoder, uint32Encoder } from "./codec/number.js"
import { Decoder, mapDecoders } from "./codec/tlsDecoder.js"
import { Encoder, contramapBufferEncoders } from "./codec/tlsEncoder.js"
import {
  numberRecordDecoder,
  varLenDataDecoder,
  numberRecordEncoder,
  varLenDataEncoder,
} from "./codec/variableLength.js"
import { CiphersuiteImpl } from "./crypto/ciphersuite.js"
import { deriveSecret } from "./crypto/kdf.js"
import { PathSecrets } from "./pathSecrets.js"
import { CryptoVerificationError } from "./mlsError.js"
import { getHpkePublicKey, RatchetTree } from "./ratchetTree.js"
import { leafToNodeIndex, toLeafIndex } from "./treemath.js"
import { constantTimeEqual } from "./util/constantTimeCompare.js"

/** @public */
export interface PrivateKeyPath {
  leafIndex: number
  privateKeys: Record<number, Uint8Array>
}

export const privateKeyPathEncoder: Encoder<PrivateKeyPath> = contramapBufferEncoders(
  [uint32Encoder, numberRecordEncoder(uint32Encoder, varLenDataEncoder)],
  (pkp) => [pkp.leafIndex, pkp.privateKeys] as const,
)

export const privateKeyPathDecoder: Decoder<PrivateKeyPath> = mapDecoders(
  [uint32Decoder, numberRecordDecoder(uint32Decoder, varLenDataDecoder)],
  (leafIndex, privateKeys) => ({
    leafIndex,
    privateKeys,
  }),
)

/**
 * Merges PrivateKeyPaths, BEWARE, if there is a conflict, this function will prioritize the second `b` parameter
 */
export function mergePrivateKeyPaths(a: PrivateKeyPath, b: PrivateKeyPath): PrivateKeyPath {
  return { ...a, privateKeys: { ...a.privateKeys, ...b.privateKeys } }
}

/** @public */
export function updateLeafKey(path: PrivateKeyPath, newKey: Uint8Array): PrivateKeyPath {
  return { ...path, privateKeys: { ...path.privateKeys, [leafToNodeIndex(toLeafIndex(path.leafIndex))]: newKey } }
}

export async function toPrivateKeyPath(
  pathSecrets: PathSecrets,
  leafIndex: number,
  cs: CiphersuiteImpl,
  tree: RatchetTree,
): Promise<PrivateKeyPath> {
  const asArray: [number, Uint8Array][] = await Promise.all(
    Object.entries(pathSecrets).map(async ([nodeIndex, pathSecret]) => {
      const nodeSecret = await deriveSecret(pathSecret, "node", cs.kdf)
      const { privateKey, publicKey } = await cs.hpke.deriveKeyPair(nodeSecret)

      // RFC 9420 Section 7.5: verify derived keys against the advertised tree before storing them.
      const node = tree[Number(nodeIndex)]
      if (node === undefined || !constantTimeEqual(await cs.hpke.exportPublicKey(publicKey), getHpkePublicKey(node))) {
        throw new CryptoVerificationError("Derived public key does not match the ratchet tree")
      }

      return [Number(nodeIndex), await cs.hpke.exportPrivateKey(privateKey)] as const
    }),
  )

  const privateKeys: Record<number, Uint8Array> = Object.fromEntries(asArray)

  return { leafIndex, privateKeys }
}
