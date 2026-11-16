//! UUID-based identifiers of entities.

use crate::macros::uuid_ids;

uuid_ids! {
    BlobId,
    CertificateId,
    ClaimId,
    ClaimSchemaId,
    CredentialId,
    CredentialSchemaFormatClaimSchemaId,
    CredentialSchemaFormatId,
    CredentialSchemaId,
    DidId,
    EntityId,
    HistoryId,
    IdentifierId,
    IdentifierTrustInformationId,
    /// Identifier of wallet/verifier instance stored on holder/verifier side
    InstanceId,
    /// Interaction ID for issuance and verification
    InteractionId,
    KeyId,
    ManagedInstanceAttestationId,
    /// Identifier of wallet/verifier instance managed on the provider side
    ManagedInstanceId,
    /// Nonce ID for OID4VCI interactions
    NonceId,
    NotificationId,
    OrganisationId,
    ProofId,
    ProofSchemaId,
    RemoteEntityCacheEntryId,
    RevocationListEntryId,
    RevocationListId,
    TransactionDataId,
    TrustCollectionId,
    TrustEntryId,
    TrustListPublicationId,
    TrustListSubscriptionId,
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
