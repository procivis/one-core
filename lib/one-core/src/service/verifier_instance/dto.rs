use shared_types::{OrganisationId, TrustCollectionId, VerifierInstanceId};

pub use crate::model::wallet_unit::{
    WalletProviderType, WalletUnit, WalletUnitOs, WalletUnitStatus,
};

#[derive(Debug, Clone)]
pub struct RegisterVerifierInstanceRequestDTO {
    pub organisation_id: OrganisationId,
    pub verifier_provider_url: String,
    pub r#type: String,
}

#[derive(Debug, Clone)]
pub struct RegisterVerifierInstanceResponseDTO {
    pub id: VerifierInstanceId,
}

#[derive(Debug, Clone)]
pub struct EditVerifierInstanceRequestDTO {
    pub trust_collections: Vec<TrustCollectionId>,
}
