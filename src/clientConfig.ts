import { AppDataUpdateCallback, defaultAppDataUpdateCallback } from "./appDataUpdate.js"
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
  appDataUpdateCallback: AppDataUpdateCallback
}

export const defaultClientConfig: ClientConfig = {
  keyRetentionConfig: defaultKeyRetentionConfig,
  lifetimeConfig: defaultLifetimeConfig,
  keyPackageEqualityConfig: defaultKeyPackageEqualityConfig,
  paddingConfig: defaultPaddingConfig,
  appDataUpdateCallback: defaultAppDataUpdateCallback,
}

/**
 * Fills in defaults for any missing ClientConfig fields, so callers that
 * constructed a config before a field existed keep working at runtime.
 */
export function resolveClientConfig(clientConfig: ClientConfig | undefined): ClientConfig {
  return clientConfig === undefined ? defaultClientConfig : { ...defaultClientConfig, ...clientConfig }
}
