/** @public */
export class MlsError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options)
    this.name = "MlsError"
  }
}

/** @public */
export class ValidationError extends MlsError {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options)
    this.name = "ValidationError"
  }
}

/** @public */
export class AuthenticationError extends MlsError {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options)
    this.name = "AuthenticationError"
  }
}

/** @public */
export class CodecError extends MlsError {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options)
    this.name = "CodecError"
  }
}

/** @public */
export class UsageError extends MlsError {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options)
    this.name = "UsageError"
  }
}

/** @public */
export class DependencyError extends MlsError {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options)
    this.name = "DependencyError"
  }
}

/** @public */
export class CryptoVerificationError extends MlsError {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options)
    this.name = "CryptoVerificationError"
  }
}

/** @public */
export class CryptoError extends MlsError {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options)
    this.name = "CryptoError"
  }
}

/** @public */
export class InternalError extends MlsError {
  constructor(message: string, options?: ErrorOptions) {
    super(`This error should never occur, if you see this please submit a bug report. Message: ${message}`, options)
    this.name = "InternalError"
  }
}
