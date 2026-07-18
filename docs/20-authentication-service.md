# Authentication Service

In order for your application to be secure you will need to define an Authentication Service.
The exact construction is out of scope for this library, but ts-mls provides an easy interface so that you can ensure every credential is properly authenticated.
For more information on the requirements of the Authentication Service, please check (RFC 9750)[https://www.ietf.org/rfc/rfc9750.html].
The RFC defines a number of steps at which credentials need to be authenticated, however you do not need to be concerned with when to authenticate the credentials, because the library takes care for of that for you.
All you need to define is how to interact with the Authentication Service and then pass it along to the various ts-mls functions.
The Authentication Service interface defines two functions: `validateCredential` and `validateSuccessorCredential`.
The `validateCredential` function is called whenever a new credential is introduced and must ensure that the credential matches the given public key.
The `validateSuccessorCredential` function is called whenever a credential is replaced (e.g. in an Update proposal) and it must ensure that the new credential is a valid continuation of the old credential.

Below is an example of how one might construct an Authentication Service client that makes HTTP calls for authenticating credentials:

```typescript
import {
  bytesToBase64,
  createGroup,
  joinGroup,
  createCommit,
  createApplicationMessage,
  createProposal,
  processMessage,
  Credential,
  defaultCredentialTypes,
  getCiphersuiteImpl,
  generateKeyPackageWithKey,
  AuthenticationService,
  generateSignatureKeyPair,
  encode,
  credentialEncoder,
} from "ts-mls"

export class AuthenticationServiceClient implements AuthenticationService {
  constructor(private readonly baseUrl: string = "https://api.example.com/auth") {}

  async registerCredential(credential: Credential, signaturePublicKey: Uint8Array): Promise<void> {
    const response = await fetch(`${this.baseUrl}/credentials`, {
      method: "POST",
      body: JSON.stringify({
        credential: encode(credentialEncoder, credential),
        signaturePublicKey: bytesToBase64(signaturePublicKey),
      }),
    })
  }

  async validateCredential(credential: Credential, signaturePublicKey: Uint8Array): Promise<boolean> {
    const response = await fetch(`${this.baseUrl}/credentials/validate`, {
      method: "POST",
      body: JSON.stringify({
        credential: encode(credentialEncoder, credential),
        signaturePublicKey: bytesToBase64(signaturePublicKey),
      }),
    })

    const { valid } = (await response.json()) as {
      valid: boolean
    }

    return valid
  }

  async validateSuccessorCredential(oldCredential: Credential, newCredential: Credential): Promise<boolean> {
    const response = await fetch(`${this.baseUrl}/credentials/validate`, {
      method: "POST",
      body: JSON.stringify({
        oldCredential: encode(credentialEncoder, oldCredential),
        newCredential: encode(credentialEncoder, newCredential),
      }),
    })

    const { valid } = (await response.json()) as {
      valid: boolean
    }

    return valid
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

let aliceGroup = await createGroup({
  context,
  groupId,
  keyPackage: alice.publicPackage,
  privateKeyPackage: alice.privatePackage,
})
```
