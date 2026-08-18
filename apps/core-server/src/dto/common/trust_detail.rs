use std::collections::HashMap;

use one_core::service::common_dto::{
    EudiIntermediaryResponseDTO, EudiTrustInformationResponseDTO,
    TrustInformationDetailResponseEnum,
};
use one_dto_mapper::{From, convert_inner};
use proc_macros::options_not_nullable;
use serde::Serialize;
use standardized_types::etsi_119_475::registration_certificate::SupervisoryAuthority;
use url::Url;
use utoipa::ToSchema;

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(TrustInformationDetailResponseEnum)]
#[serde(untagged)]
pub(crate) enum TrustInformationDetailResponseRestEnum {
    Eudi(EudiTrustInformationResponseRestDTO),
}

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(EudiTrustInformationResponseDTO)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EudiTrustInformationResponseRestDTO {
    pub name: String,
    pub website: Url,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub country: String,
    pub identifier: String,
    #[schema(example = json!([{ "de": "Demo Dienstleistung", "en": "Demo Service" }]))]
    pub service_description: Vec<HashMap<String, String>>,
    pub supervisory_authority: SupervisoryAuthority,
    #[from(with_fn = convert_inner)]
    pub intermediary: Option<EudiIntermediaryResponseRestDTO>,
    pub is_public_sector: bool,
}

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(EudiIntermediaryResponseDTO)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EudiIntermediaryResponseRestDTO {
    pub name: Option<String>,
    pub identifier: String,
    pub website: Url,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub country: String,
}

#[derive(Debug, Clone, Serialize, From, ToSchema)]
#[from("one_core::model::history::TrustResolutionResult")]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TrustResolutionResultRestEnum {
    Trusted,
    Untrusted,
    Unknown,
}
