import { Credential, CredentialCustom } from "./credential.js"
import { CredentialTypeName } from "./credentialType.js"

function createCustomCredentialType(credentialId: number): CredentialTypeName {
  return credentialId.toString() as CredentialTypeName
}

export function createCustomCredential(credentialId: number, data: Uint8Array): Credential {
  const result: CredentialCustom = {
    credentialType: createCustomCredentialType(credentialId),
    data,
  }
  return result as unknown as Credential
}
