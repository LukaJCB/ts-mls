import { decodeConfirmedTranscriptHashInput, encodeConfirmedTranscriptHashInput } from "../../src/transcriptHash.js"
import { createRoundtripTest } from "./roundtrip.js"
import { FramedContentCommit } from "../../src/framedContent.js"

const minimalContent: FramedContentCommit = {
  groupId: new Uint8Array([1]),
  epoch: 0n,
  sender: { senderType: "member", leafIndex: 0 },
  authenticatedData: new Uint8Array([2]),
  contentType: "commit",
  commit: {
    proposals: [],
    path: {
      leafNode: {
        hpkePublicKey: new Uint8Array([3]),
        signaturePublicKey: new Uint8Array([4]),
        credential: { credentialType: "basic", identity: new Uint8Array([5]) },
        capabilities: {
          versions: ["mls10"],
          ciphersuites: ["MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519"],
          extensions: [],
          proposals: [],
          credentials: [],
        },
        leafNodeSource: "commit",
        parentHash: new Uint8Array([6]),
        extensions: [],
        signature: new Uint8Array([7]),
      },
      nodes: [],
    },
  },
}

describe("ConfirmedTranscriptHashInput roundtrip", () => {
  const roundtrip = createRoundtripTest(encodeConfirmedTranscriptHashInput, decodeConfirmedTranscriptHashInput)

  test("roundtrips", () => {
    roundtrip({ wireformat: "mls_public_message", content: minimalContent, signature: new Uint8Array([8]) })
  })
})
