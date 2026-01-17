import { defaultKeyPackageEqualityConfig, KeyPackageEqualityConfig } from "./keyPackageEqualityConfig.js"
import { defaultKeyRetentionConfig, KeyRetentionConfig } from "./keyRetentionConfig.js"
import { defaultLifetimeConfig, LifetimeConfig } from "./lifetimeConfig.js"
import { defaultPaddingConfig, PaddingConfig } from "./paddingConfig.js"

/** @public */
export interface ClientConfig {
  keyRetentionConfig: KeyRetentionConfig
  lifetimeConfig: LifetimeConfig
  keyPackageEqualityConfig: KeyPackageEqualityConfig
  paddingConfig: PaddingConfig
}

export const defaultClientConfig = {
  keyRetentionConfig: defaultKeyRetentionConfig,
  lifetimeConfig: defaultLifetimeConfig,
  keyPackageEqualityConfig: defaultKeyPackageEqualityConfig,
  paddingConfig: defaultPaddingConfig,
}
