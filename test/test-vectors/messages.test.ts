import json from "../../test_vectors/messages.json"

import { hexToBytes } from "@noble/ciphers/utils"
import { decodeMlsMessage, encodeMlsMessage } from "../../src/message"
import { decodeCommit, encodeCommit } from "../../src/commit"
import { Encoder } from "../../src/codec/tlsEncoder"
import { Decoder } from "../../src/codec/tlsDecoder"
import {
  decodeAdd,
  decodeExternalInit,
  decodeGroupContextExtensions,
  decodePSK,
  decodeReinit,
  decodeRemove,
  decodeUpdate,
  encodeAdd,
  encodeExternalInit,
  encodeGroupContextExtensions,
  encodePSK,
  encodeReinit,
  encodeRemove,
  encodeUpdate,
} from "../../src/proposal"
import { decodeRatchetTree, encodeRatchetTree } from "../../src/ratchetTree"
import { decodeGroupSecrets, encodeGroupSecrets } from "../../src/groupSecrets"

test.each(json.map((x, index) => [index, x]))(`messages test vectors %i`, (_index, x) => {
  codecRoundtrip(x)
})

type Messages = {
  mls_welcome: string
  mls_group_info: string
  mls_key_package: string
  ratchet_tree: string
  group_secrets: string
  add_proposal: string
  update_proposal: string
  remove_proposal: string
  pre_shared_key_proposal: string
  re_init_proposal: string
  external_init_proposal: string
  group_context_extensions_proposal: string
  commit: string
  public_message_application: string
  public_message_proposal: string
  public_message_commit: string
  private_message: string
}

function codecRoundtrip(msgs: Messages) {
  welcome(msgs.mls_welcome)
  groupInfo(msgs.mls_group_info)
  keyPackage(msgs.mls_key_package)
  ratchetTree(msgs.ratchet_tree)
  groupSecrets(msgs.group_secrets)
  addProposal(msgs.add_proposal)
  updateProposal(msgs.update_proposal)
  removeProposal(msgs.remove_proposal)
  pskProposal(msgs.pre_shared_key_proposal)
  reinitProposal(msgs.re_init_proposal)
  externalInitProposal(msgs.external_init_proposal)
  groupContextExtension(msgs.group_context_extensions_proposal)
  commit(msgs.commit)
  publicMessageApplication(msgs.public_message_application)
  publicMessageCommit(msgs.public_message_commit)
  publicMessageProposal(msgs.public_message_proposal)
  privateMessage(msgs.private_message)
}

function welcome(s: string) {
  const inputBytes = hexToBytes(s)
  const mlsWelcome = decodeMlsMessage(inputBytes, 0)

  if (mlsWelcome === undefined || mlsWelcome[0].wireformat !== "mls_welcome") {
    throw new Error("could not decode mls welcome")
  } else {
    const reEncoded = encodeMlsMessage(mlsWelcome[0])
    expect(reEncoded).toStrictEqual(inputBytes)
  }
}

function privateMessage(s: string) {
  const inputBytes = hexToBytes(s)
  const p = decodeMlsMessage(inputBytes, 0)

  if (p === undefined || p[0].wireformat !== "mls_private_message") {
    throw new Error("could not decode mls private message")
  } else {
    const reEncoded = encodeMlsMessage(p?.[0])
    expect(reEncoded).toStrictEqual(inputBytes)
  }
}

function groupInfo(s: string) {
  const inputBytes = hexToBytes(s)
  const gi = decodeMlsMessage(inputBytes, 0)

  if (gi === undefined || gi[0].wireformat !== "mls_group_info") {
    throw new Error("could not decode mls_group_info")
  } else {
    const reEncoded = encodeMlsMessage(gi[0])
    expect(reEncoded).toStrictEqual(inputBytes)
  }
}

function keyPackage(s: string) {
  const inputBytes = hexToBytes(s)
  const kp = decodeMlsMessage(inputBytes, 0)

  if (kp === undefined || kp[0].wireformat !== "mls_key_package") {
    throw new Error("could not decode mls_key_package")
  } else {
    const reEncoded = encodeMlsMessage(kp[0])
    expect(reEncoded).toStrictEqual(inputBytes)
  }
}

function publicMessageApplication(s: string) {
  const inputBytes = hexToBytes(s)
  const p = decodeMlsMessage(inputBytes, 0)

  if (p === undefined || p[0].wireformat !== "mls_public_message") {
    throw new Error("could not decode mls_public_message")
  } else {
    expect(p[0].publicMessage.content.contentType).toBe("application")
    const reEncoded = encodeMlsMessage(p[0])
    expect(reEncoded).toStrictEqual(inputBytes)
  }
}

function publicMessageProposal(s: string) {
  const inputBytes = hexToBytes(s)
  const p = decodeMlsMessage(inputBytes, 0)

  if (p === undefined || p[0].wireformat !== "mls_public_message") {
    throw new Error("could not decode mls_public_message")
  } else {
    expect(p[0].publicMessage.content.contentType).toBe("proposal")
    const reEncoded = encodeMlsMessage(p[0])
    expect(reEncoded).toStrictEqual(inputBytes)
  }
}

function publicMessageCommit(s: string) {
  const inputBytes = hexToBytes(s)
  const p = decodeMlsMessage(inputBytes, 0)

  if (p === undefined || p[0].wireformat !== "mls_public_message") {
    throw new Error("could not decode mls_public_message")
  } else {
    expect(p[0].publicMessage.content.contentType).toBe("commit")
    const reEncoded = encodeMlsMessage(p[0])
    expect(reEncoded).toStrictEqual(inputBytes)
  }
}

//const keyPackage = createTest(encodeKeyPackage, decodeKeyPackage, '')
const commit = createTest(encodeCommit, decodeCommit, "commit")
const groupSecrets = createTest(encodeGroupSecrets, decodeGroupSecrets, "group_secrets")
const ratchetTree = createTest(encodeRatchetTree, decodeRatchetTree, "ratchet_tree")
const updateProposal = createTest(encodeUpdate, decodeUpdate, "update_proposal")
const addProposal = createTest(encodeAdd, decodeAdd, "add_proposal")
const pskProposal = createTest(encodePSK, decodePSK, "pre_shared_key_proposal")
const removeProposal = createTest(encodeRemove, decodeRemove, "remove_proposal")
const reinitProposal = createTest(encodeReinit, decodeReinit, "re_init_proposal")
const externalInitProposal = createTest(encodeExternalInit, decodeExternalInit, "external_init_proposal")
const groupContextExtension = createTest(
  encodeGroupContextExtensions,
  decodeGroupContextExtensions,
  "group_context_extensions_proposal",
)

function createTest<T>(enc: Encoder<T>, dec: Decoder<T>, typeName: string): (s: string) => void {
  return (s) => {
    const inputBytes = hexToBytes(s)
    const decoded = dec(inputBytes, 0)

    if (decoded === undefined) {
      throw new Error(`could not decode ${typeName}`)
    } else {
      const reEncoded = enc(decoded[0])
      expect(reEncoded).toStrictEqual(inputBytes)
    }
  }
}
