import { CiphersuiteImpl } from "./crypto/ciphersuite.js"
import { extensionsSupportedByCapabilities } from "./extension.js"
import { decodeFully } from "./extension.js"
import { decodeExternalSender } from "./externalSender.js"
import { GroupInfo } from "./groupInfo.js"
import { KeyPackage, PrivateKeyPackage } from "./keyPackage.js"
import { MLSMessage } from "./message.js"
import { protectExternalProposalPublic } from "./messageProtectionPublic.js"
import { UsageError, ValidationError } from "./mlsError.js"
import { Proposal } from "./proposal.js"
import { defaultProposalTypes } from "./defaultProposalType.js"
import { defaultExtensionTypes } from "./defaultExtensionType.js"
import { senderTypes } from "./sender.js"
import { constantTimeEqual } from "./util/constantTimeCompare.js"
import { wireformats } from "./wireformat.js"

/** @public */
export async function proposeAddExternal(
  groupInfo: GroupInfo,
  keyPackage: KeyPackage,
  privateKeyPackage: PrivateKeyPackage,
  cs: CiphersuiteImpl,
  authenticatedData: Uint8Array = new Uint8Array(),
): Promise<MLSMessage> {
  const allExtensionsSupported = extensionsSupportedByCapabilities(
    groupInfo.groupContext.extensions,
    keyPackage.leafNode.capabilities,
  )
  if (!allExtensionsSupported) throw new UsageError("client does not support every extension in the GroupContext")

  const proposal: Proposal = {
    proposalType: defaultProposalTypes.add,
    add: {
      keyPackage,
    },
  }

  const result = await protectExternalProposalPublic(
    privateKeyPackage.signaturePrivateKey,
    groupInfo.groupContext,
    authenticatedData,
    proposal,
    { senderType: senderTypes.new_member_proposal },
    cs,
  )

  return {
    wireformat: wireformats.mls_public_message,
    version: groupInfo.groupContext.version,
    publicMessage: result.publicMessage,
  }
}

/** @public */
export async function proposeExternal(
  groupInfo: GroupInfo,
  proposal: Proposal,
  signaturePublicKey: Uint8Array,
  signaturePrivateKey: Uint8Array,
  cs: CiphersuiteImpl,
  authenticatedData: Uint8Array = new Uint8Array(),
): Promise<MLSMessage> {
  const externalSenderExtensionIndex = groupInfo.groupContext.extensions.findIndex((ex): boolean => {
    if (ex.extensionType !== defaultExtensionTypes.external_senders) return false
    //todo can we do without the type assertion?
    const decoded = decodeFully(decodeExternalSender, ex.extensionData)

    if (decoded === undefined) throw new ValidationError("Could not decode external_sender extension")

    return constantTimeEqual(decoded.signaturePublicKey, signaturePublicKey)
  })

  if (externalSenderExtensionIndex === -1)
    throw new ValidationError("Could not find external_sender extension in groupContext.extensions")

  const result = await protectExternalProposalPublic(
    signaturePrivateKey,
    groupInfo.groupContext,
    authenticatedData,
    proposal,
    { senderType: senderTypes.external, senderIndex: externalSenderExtensionIndex },
    cs,
  )

  return {
    wireformat: wireformats.mls_public_message,
    version: groupInfo.groupContext.version,
    publicMessage: result.publicMessage,
  }
}
