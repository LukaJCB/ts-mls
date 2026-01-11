import { CiphersuiteId, CiphersuiteImpl, getCiphersuiteFromId } from "../../src/crypto/ciphersuite.js"
import { getCiphersuiteImpl } from "../../src/crypto/getCiphersuiteImpl.js"
import { hexToBytes } from "@noble/ciphers/utils.js"
import json from "../../test_vectors/welcome.json"
import { decodeMlsMessage } from "../../src/message.js"
import { makeKeyPackageRef } from "../../src/keyPackage.js"
import { constantTimeEqual } from "../../src/util/constantTimeCompare.js"
import { verifyGroupInfoConfirmationTag, verifyGroupInfoSignature } from "../../src/groupInfo.js"
import { decryptGroupInfo, decryptGroupSecrets } from "../../src/welcome.js"
import { PrivateKey } from "../../src/crypto/hpke.js"
import { wireformats } from "../../src/wireformat.js"

test.concurrent.each(json.map((x, index) => [index, x]))(`welcome test vectors %i`, async (_index, x) => {
  const impl = await getCiphersuiteImpl(getCiphersuiteFromId(x.cipher_suite as CiphersuiteId))
  await testWelcome(x.init_priv, x.key_package, x.signer_pub, x.welcome, impl)
})

async function testWelcome(
  init_priv: string,
  key_package: string,
  signer_pub: string,
  welcome: string,
  impl: CiphersuiteImpl,
) {
  const x = decodeMlsMessage(hexToBytes(welcome), 0)
  if (x === undefined || x[0].wireformat !== wireformats.mls_welcome) throw new Error("Couldn't decode to welcome")

  const w = x[0].welcome

  const y = decodeMlsMessage(hexToBytes(key_package), 0)
  if (y === undefined || y[0].wireformat !== wireformats.mls_key_package)
    throw new Error("Couldn't decode to key package")

  const keyPackageRef = await makeKeyPackageRef(y[0].keyPackage, impl.hash)

  const secret = w.secrets.find((s) => constantTimeEqual(s.newMember, keyPackageRef))

  if (secret === undefined) throw new Error("No matching secret found")

  const privKey: PrivateKey = await impl.hpke.importPrivateKey(hexToBytes(init_priv))
  const groupSecrets = await decryptGroupSecrets(privKey, keyPackageRef, w, impl.hpke)

  if (groupSecrets === undefined) throw new Error("Could not decrypt group secrets")

  const pskSecret = new Uint8Array(impl.kdf.size)

  const gi = await decryptGroupInfo(w, groupSecrets.joinerSecret, pskSecret, impl)
  if (gi === undefined) throw new Error("Could not decrypt group info")

  const tagOk = await verifyGroupInfoConfirmationTag(gi, groupSecrets.joinerSecret, pskSecret, impl)
  expect(tagOk).toBe(true)

  const signatureOk = await verifyGroupInfoSignature(gi, hexToBytes(signer_pub), impl.signature)
  expect(signatureOk).toBe(true)
}
