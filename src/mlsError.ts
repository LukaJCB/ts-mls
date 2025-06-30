export class MlsError extends Error {
  constructor(message: string) {
    super(message)
    this.name = "MlsError"
  }
}

export class ValidationError extends MlsError {
  constructor(message: string) {
    super(message)
    this.name = "ValidationError"
  }
}

export class CodecError extends MlsError {
  constructor(message: string) {
    super(message)
    this.name = "CodecError"
  }
}

export class UsageError extends MlsError {
  constructor(message: string) {
    super(message)
    this.name = "UsageError"
  }
}

export class DependencyError extends MlsError {
  constructor(message: string) {
    super(message)
    this.name = "DependencyError"
  }
}

export class CryptoVerificationError extends MlsError {
  constructor(message: string) {
    super(message)
    this.name = "CryptoVerificationError"
  }
}

export class CryptoError extends MlsError {
  constructor(message: string) {
    super(message)
    this.name = "CryptoError"
  }
}

export class InternalError extends MlsError {
  constructor(message: string) {
    super(`This error should never occur, if you see this please submit a bug report. Message: ${message}`)
    this.name = "InternalError"
  }
}
