import {
  appDataDictionaryDecoder,
  appDataDictionaryEncoder,
  AppDataDictionary,
  componentDataDecoder,
  componentDataEncoder,
  getAppDataDictionary,
  makeAppDataDictionaryExtension,
} from "../../src/appDataDictionary.js"
import { appDataUpdateDecoder, appDataUpdateEncoder, AppDataUpdate } from "../../src/appDataUpdate.js"
import { proposalDecoder, proposalEncoder, Proposal } from "../../src/proposal.js"
import { decode } from "../../src/codec/tlsDecoder.js"
import { encode } from "../../src/codec/tlsEncoder.js"
import { UsageError } from "../../src/mlsError.js"
import { createRoundtripTest } from "./roundtrip.js"

describe("ComponentData roundtrip", () => {
  const roundtrip = createRoundtripTest(componentDataEncoder, componentDataDecoder)

  test("roundtrips component data", () => {
    roundtrip({ componentId: 0x8001, data: new Uint8Array([1, 2, 3]) })
  })

  test("roundtrips empty data", () => {
    roundtrip({ componentId: 1, data: new Uint8Array([]) })
  })
})

describe("AppDataDictionary roundtrip", () => {
  const roundtrip = createRoundtripTest(appDataDictionaryEncoder, appDataDictionaryDecoder)

  test("roundtrips empty dictionary", () => {
    roundtrip([])
  })

  test("roundtrips sorted dictionary", () => {
    roundtrip([
      { componentId: 1, data: new Uint8Array([1]) },
      { componentId: 5, data: new Uint8Array([]) },
      { componentId: 0x8001, data: new Uint8Array([0xde, 0xad]) },
    ])
  })

  test("rejects unsorted dictionary", () => {
    const unsorted: AppDataDictionary = [
      { componentId: 5, data: new Uint8Array([]) },
      { componentId: 1, data: new Uint8Array([]) },
    ]
    expect(decode(appDataDictionaryDecoder, encode(appDataDictionaryEncoder, unsorted))).toBeUndefined()
  })

  test("rejects duplicate entries", () => {
    const duplicates: AppDataDictionary = [
      { componentId: 1, data: new Uint8Array([]) },
      { componentId: 1, data: new Uint8Array([1]) },
    ]
    expect(decode(appDataDictionaryDecoder, encode(appDataDictionaryEncoder, duplicates))).toBeUndefined()
  })
})

describe("AppDataDictionary extension helpers", () => {
  test("roundtrips through a GroupContext extension", () => {
    const dictionary: AppDataDictionary = [{ componentId: 2, data: new Uint8Array([7, 8, 9]) }]
    const extension = makeAppDataDictionaryExtension(dictionary)
    expect(getAppDataDictionary([extension])).toStrictEqual(dictionary)
  })

  test("returns undefined when no extension is present", () => {
    expect(getAppDataDictionary([])).toBeUndefined()
  })

  test("rejects unsorted dictionaries", () => {
    expect(() =>
      makeAppDataDictionaryExtension([
        { componentId: 5, data: new Uint8Array([]) },
        { componentId: 1, data: new Uint8Array([]) },
      ]),
    ).toThrow(UsageError)
  })
})

describe("AppDataUpdate roundtrip", () => {
  const roundtrip = createRoundtripTest(appDataUpdateEncoder, appDataUpdateDecoder)

  test("roundtrips update operation", () => {
    const update: AppDataUpdate = { componentId: 0x8001, operation: "update", update: new Uint8Array([1, 2, 3]) }
    roundtrip(update)
  })

  test("roundtrips remove operation", () => {
    const remove: AppDataUpdate = { componentId: 7, operation: "remove" }
    roundtrip(remove)
  })

  test("rejects invalid operation", () => {
    // componentId 1, operation invalid(0)
    expect(decode(appDataUpdateDecoder, new Uint8Array([0, 1, 0]))).toBeUndefined()
  })

  test("encodes the draft-09 wire format exactly", () => {
    const update: AppDataUpdate = { componentId: 0x8001, operation: "update", update: new Uint8Array([1, 2, 3]) }
    expect(encode(appDataUpdateEncoder, update)).toStrictEqual(
      new Uint8Array([0x80, 0x01, 0x01, 0x03, 0x01, 0x02, 0x03]),
    )

    const remove: AppDataUpdate = { componentId: 7, operation: "remove" }
    expect(encode(appDataUpdateEncoder, remove)).toStrictEqual(new Uint8Array([0x00, 0x07, 0x02]))

    const dictionary: AppDataDictionary = [{ componentId: 2, data: new Uint8Array([7, 8, 9]) }]
    expect(encode(appDataDictionaryEncoder, dictionary)).toStrictEqual(
      new Uint8Array([0x06, 0x00, 0x02, 0x03, 0x07, 0x08, 0x09]),
    )
  })
})

describe("app_data_update Proposal roundtrip", () => {
  const roundtrip = createRoundtripTest(proposalEncoder, proposalDecoder)

  test("roundtrips an update proposal", () => {
    const proposal: Proposal = {
      proposalType: 8,
      appDataUpdate: { componentId: 0x8001, operation: "update", update: new Uint8Array([4, 5, 6]) },
    }
    roundtrip(proposal)
  })

  test("roundtrips a remove proposal", () => {
    const proposal: Proposal = {
      proposalType: 8,
      appDataUpdate: { componentId: 0x8001, operation: "remove" },
    }
    roundtrip(proposal)
  })

  test("rejects a custom proposal with the app_data_update proposal type", () => {
    const proposal: Proposal = {
      proposalType: 8,
      proposalData: new Uint8Array([1, 2, 3]),
    }
    expect(() => encode(proposalEncoder, proposal)).toThrow(UsageError)
  })
})
