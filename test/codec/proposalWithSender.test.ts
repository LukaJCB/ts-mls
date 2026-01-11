import {
  decodeProposalWithSender,
  ProposalWithSender,
  proposalWithSenderEncoder,
} from "../../src/unappliedProposals.js"
import { ciphersuites } from "../../src/crypto/ciphersuite.js"
import { protocolVersions } from "../../src/protocolVersion.js"
import { createRoundtripTestBufferEncoder } from "./roundtrip.js"

const dummyAddProposal: ProposalWithSender = {
  proposal: {
    proposalType: "add",
    add: {
      keyPackage: {
        version: protocolVersions.mls10,
        cipherSuite: ciphersuites.MLS_256_XWING_AES256GCM_SHA512_Ed25519,
        initKey: new Uint8Array([]),
        leafNode: {
          hpkePublicKey: new Uint8Array([]),
          signaturePublicKey: new Uint8Array([]),
          credential: {
            credentialType: "basic",
            identity: new Uint8Array([]),
          },
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
  },
  senderLeafIndex: 7,
}

const dummyRemoveProposal: ProposalWithSender = {
  proposal: {
    proposalType: "remove",
    remove: { removed: 3 },
  },
  senderLeafIndex: undefined,
}

describe("ProposalWithSender roundtrip", () => {
  const roundtrip = createRoundtripTestBufferEncoder(proposalWithSenderEncoder, decodeProposalWithSender)

  test("roundtrips add with sender", () => {
    roundtrip(dummyAddProposal)
  })

  test("roundtrips remove without sender", () => {
    roundtrip(dummyRemoveProposal)
  })
})
