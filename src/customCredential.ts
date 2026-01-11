import { Credential, CredentialCustom } from "./credential.js"
import { CredentialTypeValue } from "./credentialType.js"

function createCustomCredentialType(credentialId: number): CredentialTypeValue {
  return credentialId as CredentialTypeValue
}

export function createCustomCredential(credentialId: number, data: Uint8Array): Credential {
  const result: CredentialCustom = {
    credentialType: createCustomCredentialType(credentialId),
    data,
  }
  return result as unknown as Credential
}
