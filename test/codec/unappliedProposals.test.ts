import { bytesToBase64, defaultProposalTypes, defaultCredentialTypes } from "../../src/index.js"
import { ciphersuites } from "../../src/crypto/ciphersuite.js"
import { protocolVersions } from "../../src/protocolVersion.js"
import {
  unappliedProposalsDecoder,
  UnappliedProposals,
  unappliedProposalsEncoder,
} from "../../src/unappliedProposals.js"
import { createRoundtripTestBufferEncoder } from "./roundtrip.js"
import { leafNodeSources } from "../../src/leafNodeSource.js"

const key = bytesToBase64(new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]))
const key2 = bytesToBase64(new Uint8Array([11, 12, 13, 14, 15, 16, 17, 18]))
const dummyUnapplied: UnappliedProposals = {
  [key]: {
    proposal: {
      proposalType: defaultProposalTypes.add,
      add: {
        keyPackage: {
          version: protocolVersions.mls10,
          cipherSuite: ciphersuites.MLS_256_XWING_AES256GCM_SHA512_Ed25519,
          initKey: new Uint8Array([]),
          leafNode: {
            hpkePublicKey: new Uint8Array([]),
            signaturePublicKey: new Uint8Array([]),
            credential: {
              credentialType: defaultCredentialTypes.basic,
              identity: new Uint8Array([]),
            },
            capabilities: {
              versions: [],
              ciphersuites: [],
              extensions: [],
              proposals: [],
              credentials: [],
            },
            leafNodeSource: leafNodeSources.key_package,
            lifetime: { notBefore: 0n, notAfter: 0n },
            extensions: [],
            signature: new Uint8Array([]),
          },
          extensions: [],
          signature: new Uint8Array([]),
        },
      },
    },
    senderLeafIndex: 1,
  },
  [key2]: {
    proposal: {
      proposalType: defaultProposalTypes.remove,
      remove: { removed: 99 },
    },
    senderLeafIndex: undefined,
  },
}

describe("UnappliedProposals roundtrip", () => {
  const roundtrip = createRoundtripTestBufferEncoder(unappliedProposalsEncoder, unappliedProposalsDecoder)

  test("roundtrips empty record", () => {
    roundtrip({})
  })

  test("roundtrips populated record", () => {
    roundtrip(dummyUnapplied)
  })
})
