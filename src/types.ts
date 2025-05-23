// import { CiphersuiteId, CiphersuiteName, PrivateKey, PublicKey, SecretKey } from "./crypto/ciphersuite"
// import { Hash, refhash } from "./crypto/hash"
// import { Signature, signWithLabel, verifyWithLabel } from "./crypto/signature"
// import { HPKECiphertext, Welcome } from "./welcome"
// import { PreSharedKeyID, PSKType } from "./presharedkey"
// import { ProtocolVersionName } from "./protocolVersion"

// type SenderIndex = number

// function makeKeyPackageRef(value: Uint8Array, h: Hash) {
//   return refhash("MLS 1.0 KeyPackage Reference", value, h)
// }

// function makeProposalRef(value: Uint8Array, h: Hash) {
//   return refhash("MLS 1.0 Proposal Reference", value, h)
// }

// //5.3
// type CredentialType = "basic" | "x509"

// type Credential = Readonly<
//   { credentialType: "basic"; identity: ArrayBuffer } | { credentialType: "x509"; certificates: ArrayBuffer[] }
// >

// type FramedContentTBS<C extends ContentType, S extends SenderType> = Readonly<{
//   protocolVersion: ProtocolVersion
//   wireformat: Wireformat
//   content: FramedContent<C>
//   senderContext: SenderContext<S>
// }>

// type FramedContent<C extends ContentType> = C extends C
//   ? Readonly<{
//       groupId: GroupId
//       epoch: bigint
//       sender: Sender
//       authenticatedData: Uint8Array
//       contentType: C
//       content: ContentTypeSpecificData<C>
//     }>
//   : never

// type FramedContentAuthData<C extends ContentType> = Readonly<{
//   signature: ArrayBuffer
//   confirmationTag: ConfirmationTag<C>
// }>

// type AuthenticatedContent<C extends ContentType> = Readonly<{
//   wireformat: Wireformat
//   content: FramedContent<C>
//   auth: FramedContentAuthData<C>
// }>

// type PublicMessage<C extends ContentType, S extends SenderType> = Readonly<{
//   content: FramedContent<C>
//   auth: FramedContentAuthData<C>
//   membershipTag: MembershipTag<S>
// }>

// type MAC = ArrayBuffer
// type GroupContext = Readonly<{
//   version: ProtocolVersion
//   cipherSuite: CiphersuiteId //todo
//   groupId: GroupId
//   epoch: number
//   treeHash: ArrayBuffer
//   confirmedTranscriptHash: ArrayBuffer
//   extensions: Extension[]
// }>

// type SenderContext<S extends SenderType> = S extends "member"
//   ? GroupContext
//   : S extends "new_member_commit"
//     ? GroupContext
//     : {}

// type ConfirmationTag<C extends ContentType> = C extends "commit" ? MAC : {}

// type MembershipTag<S extends SenderType> = S extends "member" ? MAC : {}

// type AuthenticatedContentTBM<C extends ContentType, S extends SenderType> = {
//   contentTBS: FramedContentTBS<C, S>
//   auth: FramedContentAuthData<C>
// }

// function createMembershipTag<C extends ContentType>(
//   membershipKey: SecretKey,
//   tbm: AuthenticatedContentTBM<C, "member">,
//   h: Hash,
// ): Promise<MAC> {
//   return h.mac(membershipKey, new ArrayBuffer()) //todo MAC()
// }

// type PrivateMessage = Readonly<{
//   groupId: GroupId
//   epoch: number
//   contentType: ContentType
//   authenticatedData: ArrayBuffer
//   encryptedSenderData: ArrayBuffer
//   ciphertext: ArrayBuffer
// }>

// type PrivateMessageContent<C extends ContentType> = Readonly<{
//   content: ContentTypeSpecificData<C>
//   auth: FramedContentAuthData<C>
//   //padding
// }>

// type PrivateContentAAD = Readonly<{
//   groupId: GroupId
//   epoch: number
//   contentType: ContentType
//   authenticatedData: ArrayBuffer
// }>

// type SenderData = Readonly<{
//   leafIndex: LeafIndex
//   generation: number
//   reuseGuard: number[]
// }>

// type SenderDataAAD = Readonly<{
//   groupId: GroupId
//   epoch: number
//   contentType: ContentType
// }>

// type CommitContent = FramedContentTBS<"commit", "new_member_commit">

// type ProposalType =
//   | "reserved"
//   | "add"
//   | "update"
//   | "remove"
//   | "psk"
//   | "reinit"
//   | "external_init"
//   | "group_context_extensions"

// type Proposal = Readonly<
//   | { proposalType: "add"; keyPackage: KeyPackage }
//   | { proposalType: "update"; leafNode: RatchetLeaf<LeafNodeSource> }
//   | { proposalType: "remove"; removed: LeafIndex }
//   | { proposalType: "psk"; preSharedKeyId: PreSharedKeyID }
//   | {
//       proposalType: "reinit"
//       groupId: GroupId
//       version: ProtocolVersion
//       cipherSuite: CiphersuiteId
//       extensions: Extension[]
//     }
//   | { proposalType: "external_init"; kemOutput: ArrayBuffer }
//   | { proposalType: "group_context_extensions"; extensions: Extension[] }
// >

// type ProposalOrRefType = "reserved" | "proposal" | "reference"
// type ProposalOrRef = Readonly<{ kind: "proposal"; proposal: Proposal } | { kind: "reference"; reference: ProposalRef }>
// type Commit = Readonly<{ proposals: ProposalOrRef[]; path: UpdatePath | undefined }>

// //10

// type ProposalRef = ArrayBuffer

// //12.4.3

// type ContentTypeSpecificData<C extends ContentType> = C extends "application"
//   ? { applicationData: ArrayBuffer }
//   : C extends "proposal"
//     ? Proposal
//     : C extends "commit"
//       ? Commit
//       : {}

// type RatchetTree = RatchetNode | RatchetLeaf<LeafNodeSource>

// type RatchetNode = Readonly<{
//   kind: "Node"
//   data: RatchetNodeData | undefined
// }>

// type RatchetLeaf<L extends LeafNodeSource> = Readonly<{
//   kind: "Leaf"
//   leaf: RatchetLeafTBS<L>
//   signature: Uint8Array
// }>

// type RatchetLeafC = RatchetLeaf<"commit">

// type RatchetLeafTBS<L extends LeafNodeSource> = Readonly<{
//   data: RatchetNodeData | undefined
//   credential: string //todo
//   signatureKey: CryptoKey
//   capabilities: Capabilities
//   leafNodeSource: L
//   leafNodeInfo: LeafNodeInfo<L>
//   extensions: Extension[]
//   leafNodeGroupInfo: LeafNodeGroupInfo<L>
// }>

// function encodeLeafTBS<L extends LeafNodeSource>(tbs: RatchetLeafTBS<L>): Uint8Array {
//   return new Uint8Array() //todo
// }

// function signLeafNode<L extends LeafNodeSource>(
//   tbs: RatchetLeafTBS<L>,
//   s: Signature,
//   signKey: PrivateKey,
// ): RatchetLeaf<L> {
//   const signature = signWithLabel(signKey, "LeafNodeTBS", encodeLeafTBS(tbs), s)
//   return { kind: "Leaf", leaf: tbs, signature: signature }
// }

// function verifyLeadNodeSignature<L extends LeafNodeSource>(
//   l: RatchetLeaf<L>,
//   s: Signature,
//   publicKey: Uint8Array,
// ): boolean {
//   return verifyWithLabel(publicKey, "LeafNodeTBS", encodeLeafTBS(l.leaf), new Uint8Array(l.signature), s)
// }

// function verifyRequiredCapabilities() {
//   return true //todo
// }

// function verifyCredentialTypeSupport() {
//   return true //todo
// }

// function verifyLifetime() {
//   return true //todo
// }

// function verifyExtensions() {
//   return true //todo
// }

// function verifyLeafNodeSource() {
//   return true //todo
// }

// function verifyUniqueKeys() {
//   return true // todo
// }

// type RatchetNodeData = Readonly<{
//   hpkePublicKey: PublicKey
//   unmergedLeaves: Set<number>
//   parentHash: ArrayBuffer
// }>

// function directPath(leafIndex: LeafIndex, tree: RatchetTree): number[] {
//   return []
// }

// function coPath(leafIndex: LeafIndex, tree: RatchetTree): number[] {
//   return []
// }

// function filteredDirectPath(leafIndex: LeafIndex, tree: RatchetTree): number[] {
//   return []
// }

// type LeafNodeSource = "reserved" | "key_package" | "update" | "commit"

// type ParentHash = ArrayBuffer
// type Capabilities = {
//   versions: string //todo
//   ciphersuites: CiphersuiteId[]
//   extensions: ExtensionType
//   proposals: string //todo
//   credentials: string //todo
// }

// type LeafNodeInfo<L extends LeafNodeSource> = L extends "key_package" ? Lifetime : L extends "commit" ? ParentHash : {}

// type LeafNodeGroupInfo<L extends LeafNodeSource> = L extends "update"
//   ? GroupIdLeafIndex
//   : L extends "commit"
//     ? GroupIdLeafIndex
//     : {}

// type GroupIdLeafIndex = Readonly<{
//   groupId: GroupId
//   leafIndex: LeafIndex
// }>

// type GroupId = string

// type LeafIndex = number

// type Lifetime = { notBefore: bigint; notAfter: bigint }

// type ExtensionType = number

// type Extension = {
//   extensionType: ExtensionType
//   extensionData: ArrayBuffer
// }

// //7.6
// type UpdatePathNode = Readonly<{
//   encryptionKey: CryptoKey
//   encryptedPathSecret: HPKECiphertext
// }>

// type UpdatePath = Readonly<{
//   leafNode: RatchetLeaf<LeafNodeSource> //todo?
//   nodes: UpdatePathNode[]
// }>

// type NodeType = "reserved" | "leaf" | "parent"

// type LeafNodeHashInput = Readonly<{
//   leafIndex: LeafIndex
//   leafNode: RatchetLeaf<LeafNodeSource> | undefined
// }>

// type ParentNodeHashInput = Readonly<{
//   parentNode: RatchetNode | undefined
//   leftHash: ArrayBuffer
//   rightHash: ArrayBuffer
// }>

// type TreeHashInput = Readonly<
//   { nodeType: "leaf"; leafNode: LeafNodeHashInput } | { nodeType: "parent"; parentNode: ParentNodeHashInput }
// >

// type ParentHashInput = Readonly<{
//   encryptionKey: CryptoKey
//   parentHash: ArrayBuffer
//   originalSiblingTreeHash: ArrayBuffer
// }>
