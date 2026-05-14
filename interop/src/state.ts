import type { CiphersuiteImpl, ClientState, KeyPackage, PrivateKeyPackage } from "../../src/index.js"

export interface GroupEntry {
  state: ClientState
  cipherSuite: CiphersuiteImpl
  wireAsPublicMessage: boolean
  pendingNewState?: ClientState
  pendingLeafUpdate?: { hpkePublicKey: Uint8Array; hpkePrivateKey: Uint8Array }
  ingestedBytes: Set<string>
}

export interface KeyPackageEntry {
  publicPackage: KeyPackage
  privatePackage: PrivateKeyPackage
  cipherSuite: CiphersuiteImpl
}

export interface ReinitEntry {
  suspendedState: ClientState
  cipherSuite: CiphersuiteImpl
  wireAsPublicMessage: boolean
  newKey?: { publicPackage: KeyPackage; privatePackage: PrivateKeyPackage }
  createdStateId?: number
}

export interface ExternalSignerEntry {
  cipherSuite: CiphersuiteImpl
  signaturePublicKey: Uint8Array
  signaturePrivateKey: Uint8Array
  identity: Uint8Array
}

export class Store {
  private groups = new Map<number, GroupEntry>()
  private pendingKeyPackages = new Map<number, KeyPackageEntry>()
  private reinits = new Map<number, ReinitEntry>()
  private externalSigners = new Map<number, ExternalSignerEntry>()
  readonly psks = new Map<string, Uint8Array>()
  private nextId = 1

  insertGroup(entry: Omit<GroupEntry, "ingestedBytes"> & { ingestedBytes?: Set<string> }): number {
    const id = this.nextId++
    this.groups.set(id, { ...entry, ingestedBytes: entry.ingestedBytes ?? new Set() })
    return id
  }

  getGroup(id: number): GroupEntry {
    const entry = this.groups.get(id)
    if (!entry) throw new Error(`Unknown state_id: ${id}`)
    return entry
  }

  updateGroup(id: number, patch: Partial<GroupEntry>): GroupEntry {
    const entry = this.getGroup(id)
    const next = { ...entry, ...patch }
    this.groups.set(id, next)
    return next
  }

  deleteGroup(id: number): void {
    this.groups.delete(id)
  }

  insertKeyPackage(entry: KeyPackageEntry): number {
    const id = this.nextId++
    this.pendingKeyPackages.set(id, entry)
    return id
  }

  takeKeyPackage(id: number): KeyPackageEntry {
    const entry = this.pendingKeyPackages.get(id)
    if (!entry) throw new Error(`Unknown transaction_id: ${id}`)
    this.pendingKeyPackages.delete(id)
    return entry
  }

  insertReinit(entry: ReinitEntry): number {
    const id = this.nextId++
    this.reinits.set(id, entry)
    return id
  }

  getReinit(id: number): ReinitEntry {
    const entry = this.reinits.get(id)
    if (!entry) throw new Error(`Unknown reinit_id: ${id}`)
    return entry
  }

  updateReinit(id: number, patch: Partial<ReinitEntry>): ReinitEntry {
    const entry = this.getReinit(id)
    const next = { ...entry, ...patch }
    this.reinits.set(id, next)
    return next
  }

  insertExternalSigner(entry: ExternalSignerEntry): number {
    const id = this.nextId++
    this.externalSigners.set(id, entry)
    return id
  }

  getExternalSigner(id: number): ExternalSignerEntry {
    const entry = this.externalSigners.get(id)
    if (!entry) throw new Error(`Unknown signer_id: ${id}`)
    return entry
  }
}
