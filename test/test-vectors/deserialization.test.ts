import json from "../../test_vectors/deserialization.json"
import { hexToBytes } from "@noble/ciphers/utils"
import { determineLength } from "../../src/codec/variableLength"

test.concurrent.each(json.map((x, index) => [index, x]))("deserialization test vectors %i", (_index, x) => {
  checkLength(x.vlbytes_header, x.length)
})

function checkLength(header: string, len: number) {
  const { length } = determineLength(hexToBytes(header))
  expect(length).toBe(len)
}
