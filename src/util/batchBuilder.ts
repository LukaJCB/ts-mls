export type BatchBuilder<T> = {
  currentBatch: T[]
  batches: T[][]
  batchSize: number
}
export function initBatchBuilder<T>(batchSize: number): BatchBuilder<T> {
  const currentBatch = new Array<T>()
  const batches = new Array<T[]>()
  return { currentBatch, batches, batchSize }
}

export function addBatchBuilder<T>(b: BatchBuilder<T>, t: T): void {
  b.currentBatch.push(t)

  if (b.currentBatch.length == b.batchSize) {
    b.batches.push(b.currentBatch)
    b.currentBatch = new Array<T>()
  }
}

export function finalizeBatchBuilder<T>(b: BatchBuilder<T>): T[][] {
  if (b.currentBatch.length > 0) {
    b.batches.push(b.currentBatch)
  }

  return b.batches
}
