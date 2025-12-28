import { Decoder, mapDecoder } from "./tlsDecoder.js"
import { BufferEncoder, contramapBufferEncoder, encode, Encoder } from "./tlsEncoder.js"
import { decodeVarLenData, varLenDataEncoder } from "./variableLength.js"

export const stringEncoder: BufferEncoder<string> = contramapBufferEncoder(varLenDataEncoder, (s) =>
  new TextEncoder().encode(s),
)

export const encodeString: Encoder<string> = encode(stringEncoder)

export const decodeString: Decoder<string> = mapDecoder(decodeVarLenData, (u) => new TextDecoder().decode(u))
