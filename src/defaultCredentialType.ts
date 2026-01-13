/** @public */
export const defaultCredentialTypes = {
  basic: 1,
  x509: 2,
} as const

/** @public */
export type DefaultCredentialTypeName = keyof typeof defaultCredentialTypes
/** @public */
export type DefaultCredentialTypeValue = (typeof defaultCredentialTypes)[DefaultCredentialTypeName]

const defaultCredentialTypeValues = new Set<number>(Object.values(defaultCredentialTypes))

export function defaultCredentialTypeValueFromName(name: DefaultCredentialTypeName): DefaultCredentialTypeValue {
  return defaultCredentialTypes[name]
}

export function isDefaultCredentialTypeValue(v: number): v is DefaultCredentialTypeValue {
  return defaultCredentialTypeValues.has(v)
}
