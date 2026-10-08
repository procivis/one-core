use std::collections::HashMap;

use one_core::service::common_dto::{
    EudiIntermediaryResponseDTO, EudiTrustInformationResponseDTO, TrustInformationDetailResponseDTO,
};
use one_dto_mapper::{From, convert_inner};
use standardized_types::etsi_119_475::registration_certificate::SupervisoryAuthority;

use super::history::EcosystemOutcomeBindingDTO;
use super::mapper::{convert_ecosystem_errors, from_i18n_strings};

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(TrustInformationDetailResponseDTO)]
#[uniffi(name = "TrustInformationDetail")]
pub struct TrustInformationDetailResponseBindingDTO {
    #[from(with_fn = convert_inner)]
    pub ecosystem: Option<String>,
    #[from(with_fn = convert_inner)]
    pub issuer: Option<TrustInformationDetailResponseBindingEnum>,
    #[from(with_fn = convert_inner)]
    pub verifier: Option<TrustInformationDetailResponseBindingEnum>,
    /// One entry per ecosystem provider that rejected the artifact, keyed by provider id.
    #[from(with_fn_ref = "convert_ecosystem_errors")]
    pub ecosystem_errors: HashMap<String, EcosystemOutcomeBindingDTO>,
}

#[derive(Clone, Debug, uniffi::Enum)]
#[uniffi(name = "TrustInformationDetailInfo")]
pub enum TrustInformationDetailResponseBindingEnum {
    Eudi(EudiTrustInformationResponseBindingDTO),
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(EudiTrustInformationResponseDTO)]
#[uniffi(name = "EudiTrustInformation")]
pub struct EudiTrustInformationResponseBindingDTO {
    pub name: String,
    #[from(with_fn = convert_inner)]
    pub support_url: Option<String>,
    #[from(with_fn = convert_inner)]
    pub info_url: Option<String>,
    #[from(with_fn = convert_inner)]
    pub privacy_policy_url: Option<String>,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub country: String,
    pub identifier: String,
    #[from(with_fn = from_i18n_strings)]
    pub service_description: Vec<HashMap<String, String>>,
    pub supervisory_authority: EudiSupervisoryAuthorityResponseBindingDTO,
    #[from(with_fn = convert_inner)]
    pub intermediary: Option<EudiIntermediaryResponseBindingDTO>,
    pub is_public_sector: bool,
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(SupervisoryAuthority)]
#[uniffi(name = "EudiSupervisoryAuthority")]
pub(crate) struct EudiSupervisoryAuthorityResponseBindingDTO {
    pub email: String,
    pub phone: String,
    pub uri: String,
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(EudiIntermediaryResponseDTO)]
#[uniffi(name = "EudiIntermediary")]
pub struct EudiIntermediaryResponseBindingDTO {
    pub name: Option<String>,
    pub identifier: String,
    #[from(with_fn = convert_inner)]
    pub support_url: Option<String>,
    #[from(with_fn = convert_inner)]
    pub info_url: Option<String>,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub country: String,
}
