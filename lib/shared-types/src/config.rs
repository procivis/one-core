//! String identifiers referring to entries of the core configuration.

use crate::macros::string_ids;

string_ids! {
    /// Identifier of a formatter based in CoreConfig.format
    CredentialFormat,
    /// Identifier of a DID method based in CoreConfig.did
    DidMethodId,
    /// Identifier of a document signer provider based in CoreConfig.document_signer_provider
    DocumentSignerProviderId,
    /// Identifier of an ecosystem based in CoreConfig.ecosystem
    EcosystemId,
    /// Identifier of an issuance protocol based in CoreConfig.issuance_protocol
    IssuanceProtocolId,
    /// Identifier of a key storage based in CoreConfig.key_storage
    KeyStorageId,
    /// Identifier of a revocation method based in CoreConfig.revocation
    RevocationMethodId,
    /// Identifier of a signer based in CoreConfig.signer
    SignerId,
    /// Identifier of a task based in CoreConfig.task
    TaskId,
    /// Identifier of a transport based in CoreConfig.transport
    TransportId,
    /// Identifier of a trust list publisher based in CoreConfig.trust_list_publisher
    TrustListPublisherId,
    /// Identifier of a trust list subscriber based in CoreConfig.trust_list_subscriber
    TrustListSubscriberId,
    /// Identifier of a verification protocol based in CoreConfig.verification_protocol
    VerificationProtocolId,
    /// Identifier of a verifier provider based in CoreConfig.verifier_provider
    VerifierProviderId,
    /// Identifier of a wallet provider based in CoreConfig.wallet_provider
    WalletProviderId,
}
