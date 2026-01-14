import { groupSecretsEncoder, decodeGroupSecrets } from "../../src/groupSecrets.js"
import { pskTypes } from "../../src/presharedkey.js"
import { createRoundtripTest } from "./roundtrip.js"

describe("GroupSecrets roundtrip", () => {
  const roundtrip = createRoundtripTest(groupSecretsEncoder, decodeGroupSecrets)

  test("roundtrips minimal", () => {
    roundtrip({ joinerSecret: new Uint8Array([1]), pathSecret: undefined, psks: [] })
  })

  test("roundtrips nontrivial", () => {
    roundtrip({
      joinerSecret: new Uint8Array([2, 3, 4]),
      pathSecret: new Uint8Array([5, 6, 7]),
      psks: [
        { psktype: pskTypes.external, pskId: new Uint8Array([8, 9, 10]), pskNonce: new Uint8Array([11, 12, 13, 14]) },
      ],
    })
  })
})
