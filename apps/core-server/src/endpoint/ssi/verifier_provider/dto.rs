use one_core::provider::verifier::model::{FeatureFlags, VerifierAppVersion, VerifierUpdateScreen};
use one_core::service::verifier_provider::dto::{
    DisplayNameDTO, ProviderTrustCollectionDTO, VerifierProviderMetadataResponseDTO,
};
use one_dto_mapper::{From, convert_inner};
use proc_macros::options_not_nullable;
use serde::Serialize;
use shared_types::TrustCollectionId;
use utoipa::ToSchema;

#[options_not_nullable]
#[derive(Clone, From, Serialize, ToSchema)]
#[from(VerifierProviderMetadataResponseDTO)]
#[serde(rename_all = "camelCase")]
pub struct VerifierProviderResponseDTO {
    pub verifier_name: String,
    #[from(with_fn = convert_inner)]
    pub app_version: Option<VerifierProviderAppVersionResponseDTO>,
    #[from(with_fn = convert_inner)]
    trust_collections: Vec<ProviderTrustCollectionRestDTO>,
    feature_flags: FeatureFlagsRestDTO,
}

#[options_not_nullable]
#[derive(Clone, From, Serialize, ToSchema)]
#[from(VerifierAppVersion)]
#[serde(rename_all = "camelCase")]
pub struct VerifierProviderAppVersionResponseDTO {
    pub minimum: Option<String>,
    pub minimum_recommended: Option<String>,
    pub reject: Option<Vec<String>>,
    #[from(with_fn = convert_inner)]
    pub update_screen: Option<VerifierProviderUpdateScreenResponseDTO>,
}

#[derive(Clone, From, Serialize, ToSchema)]
#[from(VerifierUpdateScreen)]
#[serde(rename_all = "camelCase")]
pub struct VerifierProviderUpdateScreenResponseDTO {
    pub link: String,
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(FeatureFlags)]
pub struct FeatureFlagsRestDTO {
    pub trust_ecosystems_enabled: bool,
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(ProviderTrustCollectionDTO)]
pub(crate) struct ProviderTrustCollectionRestDTO {
    pub id: TrustCollectionId,
    pub name: String,
    pub logo: String,
    #[from(with_fn = convert_inner)]
    pub display_name: Vec<DisplayNameRestDTO>,
    #[from(with_fn = convert_inner)]
    pub description: Vec<DisplayNameRestDTO>,
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(DisplayNameDTO)]
pub(crate) struct DisplayNameRestDTO {
    pub lang: String,
    pub value: String,
}
