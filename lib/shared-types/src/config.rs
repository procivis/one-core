//! String identifiers referring to entries of the core configuration.

use crate::macros::string_ids;

string_ids! {
    /// Identifier of a formatter based in CoreConfig.format
    CredentialFormat,
    /// Identifier of a DID method based in CoreConfig.did
    DidMethodId,
    /// Identifier of an ecosystem based in CoreConfig.ecosystem
    EcosystemId,
    /// Identifier of a revocation method based in CoreConfig.revocation
    RevocationMethodId,
    /// Identifier of a signer based in CoreConfig.signer
    SignerId,
    /// Identifier of a task based in CoreConfig.task
    TaskId,
    /// Identifier of a trust list publisher based in CoreConfig.trust_list_publisher
    TrustListPublisherId,
    /// Identifier of a trust list subscriber based in CoreConfig.trust_list_subscriber
    TrustListSubscriberId,
}
