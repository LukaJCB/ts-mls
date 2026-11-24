# Authentication Service

In order for your application to be secure you will need to define an Authentication Service.
The exact construction is out of scope for this library, but ts-mls provides an easy interface so that you can ensure every credential is properly authenticated.
For more information on the requirements of the Authentication Service, please check [RFC 9750](https://www.ietf.org/rfc/rfc9750.html).
The RFC defines a number of steps at which credentials need to be authenticated, however you do not need to be concerned with when to authenticate the credentials, because the library takes care for of that for you.
All you need to define is how to interact with the Authentication Service and then pass it along to the various ts-mls functions.
The Authentication Service interface defines three validation functions: `validateCredential`, `validateSuccessorCredential`, and `validateCredentialBatch`. Each returns an `AuthenticationResult`: return `{ kind: "ok" }` when validation succeeds, or `{ kind: "error", error: "..." }` when it fails.

The `validateCredential` function validates a credential and its signature public key.
The `validateSuccessorCredential` function receives both the old and new credential/public-key pairs. It must validate the new binding and ensure that it is a valid continuation of the old binding.
The `validateCredentialBatch` function receives an array of batches (`CredentialBatchItem[][]`). Each item contains a `credential`, a `signaturePublicKey`, and optionally an `oldCredential` containing the previous credential/public-key pair. When `oldCredential` is present, the batch implementation must perform the same successor validation as `validateSuccessorCredential`, not just authenticate the new credential independently. Return success only if every item in every batch is valid.

`batchSize` must be at least 1 and controls the maximum number of items in each inner batch. Implement all three methods consistently: proposal and commit validation use the batch method even for a single item, while other validation paths can use the individual methods.

Below is an example of how one might construct an Authentication Service client that makes HTTP calls for authenticating credentials:

```typescript
import {
  bytesToBase64,
  createGroup,
  type AuthenticationResult,
  type Credential,
  type CredentialWithKey,
  type CredentialBatchItem,
  defaultCredentialTypes,
  getCiphersuiteImpl,
  generateKeyPackageWithKey,
  type AuthenticationService,
  generateSignatureKeyPair,
  encode,
  credentialEncoder,
} from "ts-mls"

export class AuthenticationServiceClient implements AuthenticationService {
  readonly batchSize = 32

  constructor(private readonly baseUrl: string = "https://api.example.com/auth") {}

  private serializeCredential({ credential, signaturePublicKey }: CredentialWithKey) {
    return {
      credential: bytesToBase64(encode(credentialEncoder, credential)),
      signaturePublicKey: bytesToBase64(signaturePublicKey),
    }
  }

  async registerCredential(credential: Credential, signaturePublicKey: Uint8Array): Promise<void> {
    const response = await fetch(`${this.baseUrl}/credentials`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(this.serializeCredential({ credential, signaturePublicKey })),
    })

    if (!response.ok) throw new Error(`Credential registration failed: HTTP ${response.status}`)
  }

  private async validate(path: string, payload: unknown): Promise<AuthenticationResult> {
    const response = await fetch(`${this.baseUrl}${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    })

    if (!response.ok) {
      return { kind: "error", error: `Authentication service returned HTTP ${response.status}` }
    }

    const { valid, error } = (await response.json()) as {
      valid: boolean
      error?: string
    }

    return valid === true ? { kind: "ok" } : { kind: "error", error: error ?? "Credential validation was rejected" }
  }

  async validateCredential(credential: Credential, signaturePublicKey: Uint8Array): Promise<AuthenticationResult> {
    return this.validate("/credentials/validate", this.serializeCredential({ credential, signaturePublicKey }))
  }

  async validateSuccessorCredential(
    oldCredential: CredentialWithKey,
    newCredential: CredentialWithKey,
  ): Promise<AuthenticationResult> {
    return this.validate("/credentials/validate-successor", {
      oldCredential: this.serializeCredential(oldCredential),
      newCredential: this.serializeCredential(newCredential),
    })
  }

  async validateCredentialBatch(batches: CredentialBatchItem[][]): Promise<AuthenticationResult> {
    // Send batches sequentially; each request contains at most batchSize items.
    for (const batch of batches) {
      const result = await this.validate("/credentials/validate-batch", {
        credentials: batch.map(({ credential, signaturePublicKey, oldCredential }) => ({
          ...this.serializeCredential({ credential, signaturePublicKey }),
          // The server must validate successor relationships whenever this field is present.
          oldCredential: oldCredential === undefined ? undefined : this.serializeCredential(oldCredential),
        })),
      })

      if (result.kind === "error") return result
    }

    return { kind: "ok" }
  }
}

//Setup the Ciphersuite and the AuthenticationService
const cipherSuite = await getCiphersuiteImpl("MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519")

const authService = new AuthenticationServiceClient()
const context = { cipherSuite, authService }

// Setup and register credentials
const aliceCredential: Credential = {
  credentialType: defaultCredentialTypes.basic,
  identity: new TextEncoder().encode("alice"),
}

const signatureKeyPair = await generateSignatureKeyPair(cipherSuite)

await authService.registerCredential(aliceCredential, signatureKeyPair.publicKey)

// Generate a new KeyPackage and create a new group
const alice = await generateKeyPackageWithKey({
  credential: aliceCredential,
  cipherSuite,
  signatureKeyPair,
})

const groupId = new TextEncoder().encode("group1")

const aliceGroup = await createGroup({
  context,
  groupId,
  keyPackage: alice.publicPackage,
  privateKeyPackage: alice.privatePackage,
})
```
