import { HkdfSha256, HkdfSha384, HkdfSha512, KdfInterface } from "@hpke/core"
import { bytesToBuffer } from "../../../util/byteArray"
import { Kdf, KdfAlgorithm } from "../../kdf"

export function makeKdfImpl(k: KdfInterface): Kdf {
  return {
    async extract(salt: Uint8Array, ikm: Uint8Array): Promise<Uint8Array> {
      const result = await k.extract(bytesToBuffer(salt), bytesToBuffer(ikm))
      return new Uint8Array(result)
    },
    async expand(prk: Uint8Array, info: Uint8Array, len: number): Promise<Uint8Array> {
      const result = await k.expand(bytesToBuffer(prk), bytesToBuffer(info), len)
      return new Uint8Array(result)
    },
    size: k.hashSize,
  }
}

export function makeKdf(kdfAlg: KdfAlgorithm): KdfInterface {
  switch (kdfAlg) {
    case "HKDF-SHA256":
      return new HkdfSha256()
    case "HKDF-SHA384":
      return new HkdfSha384()
    case "HKDF-SHA512":
      return new HkdfSha512()
  }
}
