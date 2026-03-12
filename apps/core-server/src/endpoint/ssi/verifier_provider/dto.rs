use one_core::provider::verifier::model::{Verifier, VerifierAppVersion, VerifierUpdateScreen};
use one_dto_mapper::{From, convert_inner};
use proc_macros::options_not_nullable;
use serde::Serialize;
use utoipa::ToSchema;

#[options_not_nullable]
#[derive(Clone, From, Serialize, ToSchema)]
#[from(Verifier)]
#[serde(rename_all = "camelCase")]
pub struct VerifierProviderResponseDTO {
    pub verifier_name: String,
    #[from(with_fn = convert_inner)]
    pub app_version: Option<VerifierProviderAppVersionResponseDTO>,
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
