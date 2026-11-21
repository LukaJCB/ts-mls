import { defaultKeyPackageEqualityConfig, KeyPackageEqualityConfig } from "./keyPackageEqualityConfig.js"
import { defaultKeyRetentionConfig, KeyRetentionConfig } from "./keyRetentionConfig.js"
import { defaultLifetimeConfig, LifetimeConfig } from "./lifetimeConfig.js"
import { defaultPaddingConfig, PaddingConfig } from "./paddingConfig.js"
import type { GroupContextExtension } from "./extension.js"
import type { ProposalWithSender } from "./unappliedProposals.js"

/**
 * Applies non-default proposals (for example AppDataUpdate, draft-ietf-mls-extensions
 * Section 4.7) to the GroupContext extensions of the next epoch.
 * `extensions` is the list after any GroupContextExtensions proposal.
 * Return the new list, or throw to reject the Commit.
 * @public
 */
export type CustomProposalApplier = (
  extensions: GroupContextExtension[],
  proposals: ProposalWithSender[],
) => GroupContextExtension[]

/** @public */
export interface ClientConfig {
  keyRetentionConfig: KeyRetentionConfig
  lifetimeConfig: LifetimeConfig
  keyPackageEqualityConfig: KeyPackageEqualityConfig
  paddingConfig: PaddingConfig
  applyCustomProposals?: CustomProposalApplier
}

export const defaultClientConfig: ClientConfig = {
  keyRetentionConfig: defaultKeyRetentionConfig,
  lifetimeConfig: defaultLifetimeConfig,
  keyPackageEqualityConfig: defaultKeyPackageEqualityConfig,
  paddingConfig: defaultPaddingConfig,
}
