export type KeyRetentionConfig = {
  retainKeysForGenerations: number
  retainKeysForEpochs: number
}

export const defaultKeyRetentionConfig: KeyRetentionConfig = {
  retainKeysForGenerations: 10,
  retainKeysForEpochs: 4,
}
