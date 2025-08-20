import {
  CiphersuiteId,
  CiphersuiteImpl,
  getCiphersuiteFromId,
  getCiphersuiteNameFromId,
} from "../../src/crypto/ciphersuite"
import { getCiphersuiteImpl } from "../../src/crypto/getCiphersuiteImpl"
import { encodeGroupContext, GroupContext } from "../../src/groupContext"
import { hexToBytes } from "@noble/ciphers/utils"
import json from "../../test_vectors/key-schedule.json"

import { initializeEpoch, mlsExporter } from "../../src/keySchedule"

for (const [index, x] of json.entries()) {
  test(`key-schedule test vectors ${index}`, async () => {
    const cipherSuite = x.cipher_suite as CiphersuiteId
    const impl = await getCiphersuiteImpl(getCiphersuiteFromId(cipherSuite))
    await testKeySchedule(x.group_id, x.initial_init_secret, x.epochs, cipherSuite, impl)
  })
}

async function testKeySchedule(
  group_id: string,
  initial_init_secret: string,
  epochs: Epoch[],
  cipher_suite: CiphersuiteId,
  impl: CiphersuiteImpl,
) {
  await epochs.reduce(
    async (prevInitSecret, epoch, index) => {
      const initSecret = await prevInitSecret

      const gc: GroupContext = {
        version: "mls10",
        cipherSuite: getCiphersuiteNameFromId(cipher_suite),
        groupId: hexToBytes(group_id),
        epoch: BigInt(index),
        treeHash: hexToBytes(epoch.tree_hash),
        confirmedTranscriptHash: hexToBytes(epoch.confirmed_transcript_hash),
        extensions: [],
      }

      // Verify that group context matches the provided group_context value
      expect(encodeGroupContext(gc)).toStrictEqual(hexToBytes(epoch.group_context))

      const { keySchedule, joinerSecret, welcomeSecret } = await initializeEpoch(
        initSecret,
        hexToBytes(epoch.commit_secret),
        gc,
        hexToBytes(epoch.psk_secret),
        impl.kdf,
      )

      expect(joinerSecret).toStrictEqual(hexToBytes(epoch.joiner_secret))
      expect(welcomeSecret).toStrictEqual(hexToBytes(epoch.welcome_secret))
      expect(keySchedule.initSecret).toStrictEqual(hexToBytes(epoch.init_secret))
      expect(keySchedule.senderDataSecret).toStrictEqual(hexToBytes(epoch.sender_data_secret))
      expect(keySchedule.encryptionSecret).toStrictEqual(hexToBytes(epoch.encryption_secret))
      expect(keySchedule.exporterSecret).toStrictEqual(hexToBytes(epoch.exporter_secret))
      expect(keySchedule.externalSecret).toStrictEqual(hexToBytes(epoch.external_secret))
      expect(keySchedule.confirmationKey).toStrictEqual(hexToBytes(epoch.confirmation_key))
      expect(keySchedule.membershipKey).toStrictEqual(hexToBytes(epoch.membership_key))
      expect(keySchedule.resumptionPsk).toStrictEqual(hexToBytes(epoch.resumption_psk))
      expect(keySchedule.epochAuthenticator).toStrictEqual(hexToBytes(epoch.epoch_authenticator))

      //Verify the external_pub is the public key output from KEM.DeriveKeyPair(external_secret)
      const { publicKey } = await impl.hpke.deriveKeyPair(hexToBytes(epoch.external_secret))
      expect(await impl.hpke.exportPublicKey(publicKey)).toStrictEqual(hexToBytes(epoch.external_pub))

      //Verify the exporter.secret is the value output from MLS-Exporter(exporter.label, exporter.context, exporter.length)
      const exporter = await mlsExporter(
        keySchedule.exporterSecret,
        epoch.exporter.label,
        hexToBytes(epoch.exporter.context),
        epoch.exporter.length,
        impl,
      )
      expect(exporter).toStrictEqual(hexToBytes(epoch.exporter.secret))

      return keySchedule.initSecret
    },
    Promise.resolve(hexToBytes(initial_init_secret)),
  )
}

type Epoch = {
  commit_secret: string
  confirmation_key: string
  confirmed_transcript_hash: string
  encryption_secret: string
  epoch_authenticator: string
  exporter: Exporter
  exporter_secret: string
  external_pub: string
  external_secret: string
  group_context: string
  init_secret: string
  joiner_secret: string
  membership_key: string
  psk_secret: string
  resumption_psk: string
  sender_data_secret: string
  tree_hash: string
  welcome_secret: string
}

type Exporter = {
  context: string
  label: string
  length: number
  secret: string
}
