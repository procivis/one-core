//! UUID-based identifiers of entities.

use crate::macros::uuid_ids;

uuid_ids! {
    /// Identifier of a stored blob
    BlobId,
    /// Identifier of a certificate
    CertificateId,
    /// Identifier of a claim
    ClaimId,
    /// Identifier of a claim schema
    ClaimSchemaId,
    /// Identifier of a credential
    CredentialId,
    /// Identifier of the format-specific settings of a claim schema within a credential schema
    /// format
    CredentialSchemaFormatClaimSchemaId,
    /// Identifier of a format of a credential schema
    CredentialSchemaFormatId,
    /// Identifier of a credential schema
    CredentialSchemaId,
    /// Identifier of a DID
    DidId,
    /// Identifier of any entity, e.g. the subject of a history entry
    EntityId,
    /// Identifier of a history entry
    HistoryId,
    /// Identifier of an identifier
    IdentifierId,
    /// Identifier of trust information attached to an identifier
    IdentifierTrustInformationId,
    /// Identifier of wallet/verifier instance stored on holder/verifier side
    InstanceId,
    /// Interaction ID for issuance and verification
    InteractionId,
    /// Identifier of a key
    KeyId,
    /// Identifier of an attestation of a managed wallet/verifier instance
    ManagedInstanceAttestationId,
    /// Identifier of wallet/verifier instance managed on the provider side
    ManagedInstanceId,
    /// Nonce ID for OID4VCI interactions
    NonceId,
    /// Identifier of a notification
    NotificationId,
    /// Identifier of an organisation
    OrganisationId,
    /// Identifier of a proof request
    ProofId,
    /// Identifier of a proof schema
    ProofSchemaId,
    /// Identifier of a cached remote entity
    RemoteEntityCacheEntryId,
    /// Identifier of an entry of a revocation list
    RevocationListEntryId,
    /// Identifier of a revocation list
    RevocationListId,
    /// Identifier of a transaction data item of a proof request
    TransactionDataId,
    /// Identifier of a trust collection
    TrustCollectionId,
    /// Identifier of a trust list entry
    TrustEntryId,
    /// Identifier of a trust list publication
    TrustListPublicationId,
    /// Identifier of a trust list subscription
    TrustListSubscriptionId,
    /// Identifier of a wallet attestation
    WalletAttestationId,
}

/// Implements `From<$id> for EntityId` for each of the given ids.
macro_rules! entity_id_from {
    ($($id:ty),* $(,)?) => {
        $(
            impl From<$id> for EntityId {
                fn from(value: $id) -> Self {
                    Self(value.into())
                }
            }
        )*
    };
}

entity_id_from!(
    CertificateId,
    ClaimSchemaId,
    CredentialId,
    CredentialSchemaId,
    DidId,
    IdentifierId,
    InstanceId,
    KeyId,
    ManagedInstanceId,
    NotificationId,
    OrganisationId,
    ProofId,
    ProofSchemaId,
    TrustCollectionId,
    TrustListPublicationId,
    TrustListSubscriptionId,
);
