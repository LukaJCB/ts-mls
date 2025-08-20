import { CiphersuiteId, CiphersuiteImpl, getCiphersuiteFromId } from "../../src/crypto/ciphersuite"
import { getCiphersuiteImpl } from "../../src/crypto/getCiphersuiteImpl"
import { hexToBytes } from "@noble/ciphers/utils"
import json from "../../test_vectors/transcript-hashes.json"
import { decodeAuthenticatedContent } from "../../src/authenticatedContent"
import { createConfirmedHash, createInterimHash } from "../../src/transcriptHash"

for (const [index, x] of json.entries()) {
  test(`transcript-hashes test vectors ${index}`, async () => {
    const impl = await getCiphersuiteImpl(getCiphersuiteFromId(x.cipher_suite as CiphersuiteId))
    await testTranscriptHash(
      x.authenticated_content,
      x.confirmation_key,
      x.confirmed_transcript_hash_after,
      x.interim_transcript_hash_after,
      x.interim_transcript_hash_before,
      impl,
    )
  })
}

async function testTranscriptHash(
  authenticatedContent: string,
  confirmationKey: string,
  confirmedHashAfter: string,
  interimHashAfter: string,
  interimHashBefore: string,
  impl: CiphersuiteImpl,
) {
  const auth = decodeAuthenticatedContent(hexToBytes(authenticatedContent), 0)
  if (auth === undefined || auth[0].content.contentType !== "commit" || auth[0].auth.contentType !== "commit") {
    throw new Error("Could not decode authenticated content")
  }

  const confirmationTag = auth[0].auth.confirmationTag

  const verified = await impl.hash.verifyMac(
    hexToBytes(confirmationKey),
    confirmationTag,
    hexToBytes(confirmedHashAfter),
  )
  expect(verified).toBe(true)

  const input = { wireformat: auth[0].wireformat, content: auth[0].content, signature: auth[0].auth.signature }

  const computedConfirmedHash = await createConfirmedHash(hexToBytes(interimHashBefore), input, impl.hash)

  expect(computedConfirmedHash).toStrictEqual(hexToBytes(confirmedHashAfter))

  const computedInterimHash = await createInterimHash(hexToBytes(confirmedHashAfter), confirmationTag, impl.hash)
  expect(computedInterimHash).toStrictEqual(hexToBytes(interimHashAfter))
}
