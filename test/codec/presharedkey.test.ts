import {
  decodePskId,
  decodePskLabel,
  decodePskType,
  decodeResumptionPSKUsage,
  pskIdEncoder,
  pskLabelEncoder,
  pskTypeEncoder,
  resumptionPSKUsageEncoder,
  pskTypes,
  resumptionPSKUsages,
} from "../../src/presharedkey.js"
import { createRoundtripTest } from "./roundtrip.js"

test("PSKType roundtrip", () => {
  const roundtrip = createRoundtripTest(pskTypeEncoder, decodePskType)
  roundtrip(pskTypes.external)
  roundtrip(pskTypes.resumption)
})

test("ResumptionPSKUsageValue roundtrip", () => {
  const roundtrip = createRoundtripTest(resumptionPSKUsageEncoder, decodeResumptionPSKUsage)
  roundtrip(resumptionPSKUsages.application)
  roundtrip(resumptionPSKUsages.branch)
  roundtrip(resumptionPSKUsages.reinit)
})

test("PreSharedKeyID roundtrip", () => {
  dummyPskId.forEach(createRoundtripTest(pskIdEncoder, decodePskId))
})

test("PSKLabel roundtrip", () => {
  dummyPskLabel.forEach(createRoundtripTest(pskLabelEncoder, decodePskLabel))
})

const dummyByteArray = [new Uint8Array([0, 1, 2]), new Uint8Array()] as const
const dummyPskInfoResumption = [
  { usage: resumptionPSKUsages.application, pskGroupId: dummyByteArray[0], pskEpoch: 1000n },
  { usage: resumptionPSKUsages.branch, pskGroupId: dummyByteArray[1], pskEpoch: 0n },
] as const
const dummyPskInfoExternal = [{ pskId: dummyByteArray[0] }, { pskId: dummyByteArray[1] }] as const
const dummyPskId = [
  { psktype: pskTypes.external, ...dummyPskInfoExternal[0], pskNonce: dummyByteArray[0] },
  { psktype: pskTypes.resumption, ...dummyPskInfoResumption[0], pskNonce: dummyByteArray[0] },
  { psktype: pskTypes.resumption, ...dummyPskInfoResumption[1], pskNonce: dummyByteArray[1] },
] as const
const dummyPskLabel = [
  { id: dummyPskId[0], index: 99, count: 200 },
  { id: dummyPskId[1], index: 1, count: 65535 },
]
