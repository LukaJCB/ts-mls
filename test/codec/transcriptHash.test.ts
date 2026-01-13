import { confirmedTranscriptHashInputEncoder, decodeConfirmedTranscriptHashInput } from "../../src/transcriptHash.js"
import { createRoundtripTest } from "./roundtrip.js"
import { FramedContentCommit } from "../../src/framedContent.js"
import { ciphersuites } from "../../src/crypto/ciphersuite.js"
import { protocolVersions } from "../../src/protocolVersion.js"
import { defaultCredentialTypes } from "../../src/defaultCredentialType.js"
import { leafNodeSources } from "../../src/leafNodeSource.js"
import { contentTypes } from "../../src/contentType.js"
import { senderTypes } from "../../src/sender.js"
import { wireformats } from "../../src/wireformat.js"

const minimalContent: FramedContentCommit = {
  groupId: new Uint8Array([1]),
  epoch: 0n,
  sender: { senderType: senderTypes.member, leafIndex: 0 },
  authenticatedData: new Uint8Array([2]),
  contentType: contentTypes.commit,
  commit: {
    proposals: [],
    path: {
      leafNode: {
        hpkePublicKey: new Uint8Array([3]),
        signaturePublicKey: new Uint8Array([4]),
        credential: { credentialType: defaultCredentialTypes.basic, identity: new Uint8Array([5]) },
        capabilities: {
          versions: [protocolVersions.mls10],
          ciphersuites: [ciphersuites.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519],
          extensions: [],
          proposals: [],
          credentials: [],
        },
        leafNodeSource: leafNodeSources.commit,
        parentHash: new Uint8Array([6]),
        extensions: [],
        signature: new Uint8Array([7]),
      },
      nodes: [],
    },
  },
}

describe("ConfirmedTranscriptHashInput roundtrip", () => {
  const roundtrip = createRoundtripTest(confirmedTranscriptHashInputEncoder, decodeConfirmedTranscriptHashInput)

  test("roundtrips", () => {
    roundtrip({ wireformat: wireformats.mls_public_message, content: minimalContent, signature: new Uint8Array([8]) })
  })
})
