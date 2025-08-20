import {
  KemInterface,
  DhkemP256HkdfSha256,
  DhkemX25519HkdfSha256,
  DhkemX448HkdfSha512,
  DhkemP521HkdfSha512,
  DhkemP384HkdfSha384,
} from "@hpke/core"
import { DependencyError } from "../../../mlsError"
import { KemAlgorithm } from "../../kem"

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
        throw new DependencyError(
          "Optional dependency '@hpke/ml-kem' is not installed. Please install it to use this feature.",
        )
      }

    case "ML-KEM-768":
      try {
        const { MlKem768 } = await import("@hpke/ml-kem")
        return new MlKem768()
      } catch (err) {
        throw new DependencyError(
          "Optional dependency '@hpke/ml-kem' is not installed. Please install it to use this feature.",
        )
      }
    case "ML-KEM-1024":
      try {
        const { MlKem1024 } = await import("@hpke/ml-kem")
        return new MlKem1024()
      } catch (err) {
        throw new DependencyError(
          "Optional dependency '@hpke/ml-kem' is not installed. Please install it to use this feature.",
        )
      }
    case "X-Wing":
      try {
        const { XWing } = await import("@hpke/hybridkem-x-wing")
        return new XWing()
      } catch (err) {
        throw new DependencyError(
          "Optional dependency '@hpke/hybridkem-x-wing' is not installed. Please install it to use this feature.",
        )
      }
  }
}
