import { encodeProposal, decodeProposal, Proposal } from "../../src/proposal.js"
import { defaultProposalTypes } from "../../src/defaultProposalType.js"
import { ciphersuites } from "../../src/crypto/ciphersuite.js"
import { protocolVersions } from "../../src/protocolVersion.js"
import { defaultCredentialTypes } from "../../src/credentialType.js"
import { createRoundtripTest } from "./roundtrip.js"

const dummyProposalAdd: Proposal = {
  proposalType: defaultProposalTypes.add,
  add: {
    keyPackage: {
      version: protocolVersions.mls10,
      cipherSuite: ciphersuites.MLS_256_XWING_AES256GCM_SHA512_Ed25519,
      initKey: new Uint8Array([]),
      leafNode: {
        hpkePublicKey: new Uint8Array([]),
        signaturePublicKey: new Uint8Array([]),
        credential: { credentialType: defaultCredentialTypes.basic, identity: new Uint8Array([]) },
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
  proposalType: defaultProposalTypes.remove,
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
