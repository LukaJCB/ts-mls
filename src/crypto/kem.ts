import {
  DhkemP256HkdfSha256,
  DhkemP384HkdfSha384,
  DhkemP521HkdfSha512,
  DhkemX25519HkdfSha256,
  DhkemX448HkdfSha512,
  KemInterface,
} from "@hpke/core"

export type KemAlgorithm =
  | "DHKEM-P256-HKDF-SHA256"
  | "DHKEM-X25519-HKDF-SHA256"
  | "DHKEM-X448-HKDF-SHA512"
  | "DHKEM-P521-HKDF-SHA512"
  | "DHKEM-P384-HKDF-SHA384"
  | "ML-KEM-512"
  | "ML-KEM-768"
  | "ML-KEM-1024"
  | "X-Wing"

export async function makeDhKem(kemAlg: KemAlgorithm): Promise<KemInterface> {
  switch (kemAlg) {
    case "DHKEM-P256-HKDF-SHA256":
      return new DhkemP256HkdfSha256()
    case "DHKEM-X25519-HKDF-SHA256":
      return new DhkemX25519HkdfSha256()
    case "DHKEM-X448-HKDF-SHA512":
      return new DhkemX448HkdfSha512()
    case "DHKEM-P521-HKDF-SHA512":
      return new DhkemP521HkdfSha512()
    case "DHKEM-P384-HKDF-SHA384":
      return new DhkemP384HkdfSha384()
    case "ML-KEM-512":
      try {
        const { MlKem512 } = await import("@hpke/ml-kem")
        return new MlKem512()
      } catch (err) {
        throw new Error("Optional dependency '@hpke/ml-kem' is not installed. Please install it to use this feature.")
      }

    case "ML-KEM-768":
      try {
        const { MlKem768 } = await import("@hpke/ml-kem")
        return new MlKem768()
      } catch (err) {
        throw new Error("Optional dependency '@hpke/ml-kem' is not installed. Please install it to use this feature.")
      }
    case "ML-KEM-1024":
      try {
        const { MlKem1024 } = await import("@hpke/ml-kem")
        return new MlKem1024()
      } catch (err) {
        throw new Error("Optional dependency '@hpke/ml-kem' is not installed. Please install it to use this feature.")
      }
    case "X-Wing":
      try {
        const { XWing } = await import("@hpke/hybridkem-x-wing")
        return new XWing()
      } catch (err) {
        throw new Error(
          "Optional dependency '@hpke/hybridkem-x-wing' is not installed. Please install it to use this feature.",
        )
      }
  }
}
