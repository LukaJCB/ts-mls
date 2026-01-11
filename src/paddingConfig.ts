/** @public */
export type PaddingConfig =
  | { kind: "padUntilLength"; padUntilLength: number }
  | { kind: "alwaysPad"; paddingLength: number }

/** @public */
export const defaultPaddingConfig: PaddingConfig = { kind: "padUntilLength", padUntilLength: 256 }

export function byteLengthToPad(encodedLength: number, config: PaddingConfig): number {
  if (config.kind === "alwaysPad") return config.paddingLength
  else return encodedLength >= config.padUntilLength ? 0 : config.padUntilLength - encodedLength
}
