import json from "../../test_vectors/deserialization.json"
import { hexToBytes } from "@noble/ciphers/utils"
import { determineLength } from "../../src/codec/variableLength"

test("deserialization test vectors", () => {
  for (const x of json) {
    checkLength(x.vlbytes_header, x.length)
  }
})

function checkLength(header: string, len: number) {
  const { length } = determineLength(hexToBytes(header))
  expect(length).toBe(len)
}
