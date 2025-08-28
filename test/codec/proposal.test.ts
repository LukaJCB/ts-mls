import { encodeProposal, decodeProposal, Proposal } from "../../src/proposal"
import { createRoundtripTest } from "./roundtrip.js"

const dummyProposalAdd: Proposal = {
  proposalType: "add",
  add: {
    keyPackage: {
      version: "mls10",
      cipherSuite: "MLS_256_XWING_AES256GCM_SHA512_Ed25519",
      initKey: new Uint8Array([]),
      leafNode: {
        hpkePublicKey: new Uint8Array([]),
        signaturePublicKey: new Uint8Array([]),
        credential: { credentialType: "basic", identity: new Uint8Array([]) },
        capabilities: {
          versions: [],
          ciphersuites: [],
          extensions: [],
          proposals: [],
          credentials: [],
        },
        leafNodeSource: "key_package",
        lifetime: { notBefore: 0n, notAfter: 0n },
        extensions: [],
        signature: new Uint8Array([]),
      },
      extensions: [],
      signature: new Uint8Array([]),
    },
  },
}

const dummyProposalRemove: Proposal = {
  proposalType: "remove",
  remove: { removed: 42 },
}

describe("Proposal roundtrip", () => {
  const roundtrip = createRoundtripTest(encodeProposal, decodeProposal)

  test("roundtrips add", () => {
    roundtrip(dummyProposalAdd)
  })

  test("roundtrips remove", () => {
    roundtrip(dummyProposalRemove)
  })
})
