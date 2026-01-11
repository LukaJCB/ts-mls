/** @public */
export interface LifetimeConfig {
  maximumTotalLifetime: bigint
  validateLifetimeOnReceive: boolean
}

/** @public */
export const defaultLifetimeConfig: LifetimeConfig = {
  maximumTotalLifetime: 2628000n, // 1 month
  validateLifetimeOnReceive: false,
}
