import { describe, expect, test } from "vitest"

import { getCredentialFromLeafIndex, greaseValues, makeKeyPackageRef } from "../src/index.js"

describe("root exports", () => {
  test("exports key package and ratchet tree helpers", () => {
    expect(makeKeyPackageRef).toBeTypeOf("function")
    expect(getCredentialFromLeafIndex).toBeTypeOf("function")
  })

  test("exports canonical grease values", () => {
    expect(greaseValues).toStrictEqual([
      0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada,
      0xeaea,
    ])
  })
})
