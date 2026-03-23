use one_dto_mapper::{Into, convert_inner};
use serde::Deserialize;
use shared_types::TrustCollectionId;

use crate::provider::verifier::model::{FeatureFlags, VerifierAppVersion};
use crate::service::verifier_provider::dto;

#[derive(Clone, Debug, Deserialize, Into)]
#[serde(rename_all = "camelCase")]
#[into(dto::VerifierProviderMetadataResponseDTO)]
pub(super) struct VerifierProviderMetadataResponseRestDTO {
    pub verifier_name: String,
    #[into(with_fn = convert_inner)]
    pub app_version: Option<VerifierAppVersion>,
    #[into(with_fn = convert_inner)]
    pub trust_collections: Vec<ProviderTrustCollectionRestDTO>,
    pub feature_flags: FeatureFlags,
}

#[derive(Clone, Debug, Deserialize, Into)]
#[serde(rename_all = "camelCase")]
#[into(dto::ProviderTrustCollectionDTO)]
pub struct ProviderTrustCollectionRestDTO {
    pub id: TrustCollectionId,
    pub name: String,
    pub logo: String,
    #[into(with_fn = convert_inner)]
    pub display_name: Vec<DisplayNameRestDTO>,
    #[into(with_fn = convert_inner)]
    pub description: Vec<DisplayNameRestDTO>,
}

#[derive(Clone, Debug, Deserialize, Into)]
#[serde(rename_all = "camelCase")]
#[into(dto::DisplayNameDTO)]
pub struct DisplayNameRestDTO {
    pub lang: String,
    pub value: String,
}
