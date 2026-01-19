/** @public */
export interface LifetimeConfig {
  maximumTotalLifetime: bigint
  validateLifetimeOnReceive: boolean
}

/** @public */
export const defaultLifetimeConfig: LifetimeConfig = {
  maximumTotalLifetime: 10368000n, // 4 months
  validateLifetimeOnReceive: false,
}
