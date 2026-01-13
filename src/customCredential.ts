import { Credential, CredentialCustom } from "./credential.js"

function createCustomCredentialType(credentialId: number): number {
  return credentialId
}

export function createCustomCredential(credentialId: number, data: Uint8Array): Credential {
  const result: CredentialCustom = {
    credentialType: createCustomCredentialType(credentialId),
    data,
  }
  return result as unknown as Credential
}
