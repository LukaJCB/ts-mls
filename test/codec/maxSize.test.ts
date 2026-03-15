import { CodecError, decode, encode } from "../../src/index.js"
import { varLenDataDecoder, varLenDataEncoder } from "../../src/codec/variableLength.js"

describe("maxInputSize", () => {
  test("should throw codec error when exceeded", () => {
    //two bytes added through length prefix
    const x = encode(varLenDataEncoder, new Uint8Array(198))
    expect(x.byteLength).toBe(200)
    decode(varLenDataDecoder, x, 200)

    const y = encode(varLenDataEncoder, new Uint8Array(199))
    expect(y.byteLength).toBe(201)
    expect(() => decode(varLenDataDecoder, y, 200)).toThrow(
      new CodecError("Payload larger than max allowed size, increase maxInputSize if you want to decode this"),
    )
  })
})
