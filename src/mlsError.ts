/** @public */
export class MlsError extends Error {
  constructor(message: string) {
    super(message)
    this.name = "MlsError"
  }
}

/** @public */
export class ValidationError extends MlsError {
  constructor(message: string) {
    super(message)
    this.name = "ValidationError"
  }
}

/** @public */
export class CodecError extends MlsError {
  constructor(message: string) {
    super(message)
    this.name = "CodecError"
  }
}

/** @public */
export class UsageError extends MlsError {
  constructor(message: string) {
    super(message)
    this.name = "UsageError"
  }
}

/** @public */
export class DependencyError extends MlsError {
  constructor(message: string) {
    super(message)
    this.name = "DependencyError"
  }
}

/** @public */
export class CryptoVerificationError extends MlsError {
  constructor(message: string) {
    super(message)
    this.name = "CryptoVerificationError"
  }
}

/** @public */
export class CryptoError extends MlsError {
  constructor(message: string) {
    super(message)
    this.name = "CryptoError"
  }
}

/** @public */
export class InternalError extends MlsError {
  constructor(message: string) {
    super(`This error should never occur, if you see this please submit a bug report. Message: ${message}`)
    this.name = "InternalError"
  }
}
