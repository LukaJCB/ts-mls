import {
  credentialEquals,
  type CredentialBasic,
  type CredentialCustom,
  type CredentialX509,
} from "../src/credential.js"
import { defaultCredentialTypes } from "../src/defaultCredentialType.js"

describe("credentialEquals", () => {
  test("returns true for the same object reference", () => {
    const credential: CredentialBasic = {
      credentialType: defaultCredentialTypes.basic,
      identity: new Uint8Array([1, 2, 3]),
    }

    expect(credentialEquals(credential, credential)).toBe(true)
  })

  test("returns false when credential types differ", () => {
    const basic: CredentialBasic = {
      credentialType: defaultCredentialTypes.basic,
      identity: new Uint8Array([1, 2, 3]),
    }

    const custom: CredentialCustom = {
      credentialType: 999,
      data: new Uint8Array([1, 2, 3]),
    }

    expect(credentialEquals(basic, custom)).toBe(false)
  })

  describe("basic credentials", () => {
    test("returns true when identities are equal", () => {
      const a: CredentialBasic = {
        credentialType: defaultCredentialTypes.basic,
        identity: new Uint8Array([1, 2, 3]),
      }

      const b: CredentialBasic = {
        credentialType: defaultCredentialTypes.basic,
        identity: new Uint8Array([1, 2, 3]),
      }

      expect(credentialEquals(a, b)).toBe(true)
    })

    test("returns false when identities differ", () => {
      const a: CredentialBasic = {
        credentialType: defaultCredentialTypes.basic,
        identity: new Uint8Array([1, 2, 3]),
      }

      const b: CredentialBasic = {
        credentialType: defaultCredentialTypes.basic,
        identity: new Uint8Array([1, 2, 4]),
      }

      expect(credentialEquals(a, b)).toBe(false)
    })
  })

  describe("x509 credentials", () => {
    test("returns true when certificate arrays are equal", () => {
      const a: CredentialX509 = {
        credentialType: defaultCredentialTypes.x509,
        certificates: [new Uint8Array([1]), new Uint8Array([2, 3])],
      }

      const b: CredentialX509 = {
        credentialType: defaultCredentialTypes.x509,
        certificates: [new Uint8Array([1]), new Uint8Array([2, 3])],
      }

      expect(credentialEquals(a, b)).toBe(true)
    })

    test("returns false when certificate contents differ", () => {
      const a: CredentialX509 = {
        credentialType: defaultCredentialTypes.x509,
        certificates: [new Uint8Array([1]), new Uint8Array([2, 3])],
      }

      const b: CredentialX509 = {
        credentialType: defaultCredentialTypes.x509,
        certificates: [new Uint8Array([1]), new Uint8Array([2, 4])],
      }

      expect(credentialEquals(a, b)).toBe(false)
    })

    test("returns false when certificate counts differ", () => {
      const a: CredentialX509 = {
        credentialType: defaultCredentialTypes.x509,
        certificates: [new Uint8Array([1]), new Uint8Array([2])],
      }

      const b: CredentialX509 = {
        credentialType: defaultCredentialTypes.x509,
        certificates: [new Uint8Array([1])],
      }

      expect(credentialEquals(a, b)).toBe(false)
    })
  })

  describe("custom credentials", () => {
    test("returns true when data is equal", () => {
      const a: CredentialCustom = {
        credentialType: 42,
        data: new Uint8Array([9, 8, 7]),
      }

      const b: CredentialCustom = {
        credentialType: 42,
        data: new Uint8Array([9, 8, 7]),
      }

      expect(credentialEquals(a, b)).toBe(true)
    })

    test("returns false when data differs", () => {
      const a: CredentialCustom = {
        credentialType: 42,
        data: new Uint8Array([9, 8, 7]),
      }

      const b: CredentialCustom = {
        credentialType: 42,
        data: new Uint8Array([9, 8, 6]),
      }

      expect(credentialEquals(a, b)).toBe(false)
    })
  })
})
