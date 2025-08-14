import { AuthenticationService, defaultAuthenticationService } from "./authenticationService"
import { defaultKeyPackageEqualityConfig, KeyPackageEqualityConfig } from "./keyPackageEqualityConfig"
import { defaultKeyRetentionConfig, KeyRetentionConfig } from "./keyRetentionConfig"
import { defaultLifetimeConfig, LifetimeConfig } from "./lifetimeConfig"
import { defaultPaddingConfig, PaddingConfig } from "./paddingConfig"

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
