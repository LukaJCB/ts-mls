import { Decoder, mapDecoder } from "./tlsDecoder.js"
import { BufferEncoder, contramapBufferEncoder } from "./tlsEncoder.js"
import { varLenDataDecoder, varLenDataEncoder } from "./variableLength.js"

export const stringEncoder: BufferEncoder<string> = contramapBufferEncoder(varLenDataEncoder, (s) =>
  new TextEncoder().encode(s),
)

export const stringDecoder: Decoder<string> = mapDecoder(varLenDataDecoder, (u) => new TextDecoder().decode(u))
