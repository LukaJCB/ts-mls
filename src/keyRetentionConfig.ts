export interface KeyRetentionConfig {
  retainKeysForGenerations: number
  retainKeysForEpochs: number
  maximumForwardRatchetSteps: number
}

export const defaultKeyRetentionConfig: KeyRetentionConfig = {
  retainKeysForGenerations: 10,
  retainKeysForEpochs: 4,
  maximumForwardRatchetSteps: 200,
}
