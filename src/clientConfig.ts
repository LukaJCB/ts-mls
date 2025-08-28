import { AuthenticationService, defaultAuthenticationService } from "./authenticationService.js"
import { defaultKeyPackageEqualityConfig, KeyPackageEqualityConfig } from "./keyPackageEqualityConfig.js"
import { defaultKeyRetentionConfig, KeyRetentionConfig } from "./keyRetentionConfig.js"
import { defaultLifetimeConfig, LifetimeConfig } from "./lifetimeConfig.js"
import { defaultPaddingConfig, PaddingConfig } from "./paddingConfig.js"

export interface ClientConfig {
  keyRetentionConfig: KeyRetentionConfig
  lifetimeConfig: LifetimeConfig
  keyPackageEqualityConfig: KeyPackageEqualityConfig
  paddingConfig: PaddingConfig
  authService: AuthenticationService
}

export const defaultClientConfig = {
  keyRetentionConfig: defaultKeyRetentionConfig,
  lifetimeConfig: defaultLifetimeConfig,
  keyPackageEqualityConfig: defaultKeyPackageEqualityConfig,
  paddingConfig: defaultPaddingConfig,
  authService: defaultAuthenticationService,
}
