declare const __brand: unique symbol

/** @public */
export type Brand<T, B> = T & { [__brand]: B }
