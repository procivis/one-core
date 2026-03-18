use shared_types::TrustCollectionId;

use crate::provider::verifier::model::{FeatureFlags, VerifierAppVersion};

#[derive(Clone, Debug)]
pub struct VerifierProviderMetadataResponseDTO {
    pub verifier_name: String,
    pub app_version: Option<VerifierAppVersion>,
    pub trust_collections: Vec<ProviderTrustCollectionDTO>,
    pub feature_flags: FeatureFlags,
}

#[derive(Clone, Debug)]
pub struct ProviderTrustCollectionDTO {
    pub id: TrustCollectionId,
    pub name: String,
    pub logo: String,
    pub display_name: Vec<DisplayNameDTO>,
    pub description: Vec<DisplayNameDTO>,
}

#[derive(Clone, Debug)]
pub struct DisplayNameDTO {
    pub lang: String,
    pub value: String,
}
