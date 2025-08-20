import json from "../../test_vectors/crypto-basics.json"
import { CiphersuiteId, CiphersuiteImpl, getCiphersuiteFromId } from "../../src/crypto/ciphersuite"
import { getCiphersuiteImpl } from "../../src/crypto/getCiphersuiteImpl"
import { bytesToHex, hexToBytes } from "@noble/ciphers/utils"
import { signWithLabel, verifyWithLabel } from "../../src/crypto/signature"
import { refhash } from "../../src/crypto/hash"
import { deriveSecret, deriveTreeSecret, expandWithLabel } from "../../src/crypto/kdf"
import { decryptWithLabel, encryptWithLabel } from "../../src/crypto/hpke"

for (const [index, x] of json.entries()) {
  test(`crypto-basics test vectors ${index}`, async () => {
    const impl = await getCiphersuiteImpl(getCiphersuiteFromId(x.cipher_suite as CiphersuiteId))
    await testRefHash(impl, x.ref_hash)
    await testDeriveSecret(impl, x.derive_secret)
    await testDeriveTreeSecret(impl, x.derive_tree_secret)
    await testExpandWithLabel(impl, x.expand_with_label)
    await testEncryptWithLabel(impl, x.encrypt_with_label)
    await testSignWithLabel(impl, x.sign_with_label)
  })
}

async function testDeriveSecret(impl: CiphersuiteImpl, o: { label: string; secret: string; out: string }) {
  //out == DeriveSecret(secret, label)
  const res = await deriveSecret(hexToBytes(o.secret), o.label, impl.kdf)
  expect(bytesToHex(res)).toBe(o.out)
}

async function testDeriveTreeSecret(
  impl: CiphersuiteImpl,
  o: { label: string; secret: string; generation: number; out: string },
) {
  //out == DeriveTreeSecret(secret, label, generation, length)
  const res = await deriveTreeSecret(hexToBytes(o.secret), o.label, o.generation, impl.kdf.size, impl.kdf)
  expect(bytesToHex(res)).toBe(o.out)
}

async function testExpandWithLabel(
  impl: CiphersuiteImpl,
  o: { label: string; secret: string; length: number; context: string; out: string },
) {
  //out == ExpandWithLabel(secret, label, context, length)
  const res = await expandWithLabel(hexToBytes(o.secret), o.label, hexToBytes(o.context), o.length, impl.kdf)
  expect(bytesToHex(res)).toBe(o.out)
}

async function testRefHash(impl: CiphersuiteImpl, o: { label: string; value: string; out: string }) {
  //out == RefHash(label, value)
  const res = await refhash(o.label, hexToBytes(o.value), impl.hash)
  expect(bytesToHex(res)).toBe(o.out)
}

async function testSignWithLabel(
  impl: CiphersuiteImpl,
  o: { label: string; content: string; priv: string; pub: string; signature: string },
) {
  //VerifyWithLabel(pub, label, content, signature) == true
  const v = await verifyWithLabel(
    hexToBytes(o.pub),
    o.label,
    hexToBytes(o.content),
    hexToBytes(o.signature),
    impl.signature,
  )
  expect(v).toBe(true)

  //VerifyWithLabel(pub, label, content, SignWithLabel(priv, label, content)) == true
  const signature = await signWithLabel(hexToBytes(o.priv), o.label, hexToBytes(o.content), impl.signature)
  const v2 = await verifyWithLabel(hexToBytes(o.pub), o.label, hexToBytes(o.content), signature, impl.signature)
  expect(v2).toBe(true)
}

async function testEncryptWithLabel(
  impl: CiphersuiteImpl,
  o: {
    ciphertext: string
    context: string
    kem_output: string
    label: string
    plaintext: string
    priv: string
    pub: string
  },
) {
  const privateKey = await impl.hpke.importPrivateKey(hexToBytes(o.priv))
  const publicKey = await impl.hpke.importPublicKey(hexToBytes(o.pub))

  //DecryptWithLabel(priv, label, context, kem_output, ciphertext) == plaintext
  const decrypted = await decryptWithLabel(
    privateKey,
    o.label,
    hexToBytes(o.context),
    hexToBytes(o.kem_output),
    hexToBytes(o.ciphertext),
    impl.hpke,
  )

  expect(bytesToHex(new Uint8Array(decrypted))).toBe(o.plaintext)

  //kem_output_candidate, ciphertext_candidate = EncryptWithLabel(pub, label, context, plaintext)
  const { ct: ctCandidate, enc: encCandidate } = await encryptWithLabel(
    publicKey,
    o.label,
    hexToBytes(o.context),
    hexToBytes(o.plaintext),
    impl.hpke,
  )

  //DecryptWithLabel(priv, label, context, kem_output_candidate, ciphertext_candidate) == plaintext
  const plaintext = await decryptWithLabel(
    privateKey,
    o.label,
    hexToBytes(o.context),
    encCandidate,
    ctCandidate,
    impl.hpke,
  )
  expect(bytesToHex(new Uint8Array(plaintext))).toBe(o.plaintext)
}
