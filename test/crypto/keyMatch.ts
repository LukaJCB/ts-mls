import { ClientState } from "../../src/clientState"
import { CiphersuiteImpl } from "../../src/crypto/ciphersuite"
import { Hpke } from "../../src/crypto/hpke"
import { Signature } from "../../src/crypto/signature"
import { getHpkePublicKey } from "../../src/ratchetTree"

export async function hpkeKeysMatch(publicKey: Uint8Array, privateKey: Uint8Array, hpke: Hpke): Promise<boolean> {
  const encoder = new TextEncoder()
  const plaintext = encoder.encode("test")
  const info = encoder.encode("key check")

  try {
    const { ct, enc } = await hpke.seal(await hpke.importPublicKey(publicKey), plaintext, info)

    const decrypted = await hpke.open(await hpke.importPrivateKey(privateKey), enc, ct, info)

    return new TextDecoder().decode(decrypted) === "test"
  } catch (err) {
    return false
  }
}

export async function signatureKeysMatch(
  publicKey: Uint8Array,
  privateKey: Uint8Array,
  s: Signature,
): Promise<boolean> {
  const testMessage = new TextEncoder().encode("test")
  const signature = await s.sign(privateKey, testMessage)
  return s.verify(publicKey, testMessage, signature)
}

export async function checkHpkeKeysMatch(group: ClientState, impl: CiphersuiteImpl): Promise<void> {
  for (const [nodeIndex, privateKey] of Object.entries(group.privatePath.privateKeys)) {
    const pub = getHpkePublicKey(group.ratchetTree[Number(nodeIndex)]!)
    const x = await hpkeKeysMatch(pub, privateKey, impl.hpke)
    expect(x).toBe(true)
  }
}
