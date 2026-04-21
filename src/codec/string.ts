import { Decoder, mapDecoder } from "./tlsDecoder.js"
import { Encoder, contramapBufferEncoder } from "./tlsEncoder.js"
import { varLenDataDecoder, varLenDataEncoder } from "./variableLength.js"

const _textEncoder = new TextEncoder()
const _textDecoder = new TextDecoder()

export const stringEncoder: Encoder<string> = contramapBufferEncoder(varLenDataEncoder, (s) => _textEncoder.encode(s))

export const stringDecoder: Decoder<string> = mapDecoder(varLenDataDecoder, (u) => _textDecoder.decode(u))
