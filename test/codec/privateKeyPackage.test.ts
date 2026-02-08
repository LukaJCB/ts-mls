import { privateKeyPackageEncoder, privateKeyPackageDecoder } from "../../src/keyPackage.js"
import { createRoundtripTestBufferEncoder } from "./roundtrip.js"

describe("PrivateKeyPackage codec", () => {
  const roundtrip = createRoundtripTestBufferEncoder(privateKeyPackageEncoder, privateKeyPackageDecoder)

  it("roundtrips", () => {
    roundtrip({
      initPrivateKey: new Uint8Array([10, 20, 30, 40, 50]),
      hpkePrivateKey: new Uint8Array([60, 70, 80, 90, 100]),
      signaturePrivateKey: new Uint8Array([110, 120, 130, 140, 150]),
    })
  })
})
