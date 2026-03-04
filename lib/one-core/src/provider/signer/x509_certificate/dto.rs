use one_dto_mapper::{From, Into, convert_inner};
use serde::{Deserialize, Serialize};
use serde_with::{DurationSeconds, serde_as};
use shared_types::RevocationMethodId;
use time::Duration;

use crate::proto::csr_creator::CsrRequestSubject;
use crate::service::identifier::dto::{
    CreateSelfSignedCertificateAuthorityContentRequestDTO,
    CreateSelfSignedCertificateAuthorityIssuerAlternativeNameRequest,
    CreateSelfSignedCertificateAuthorityIssuerAlternativeNameType,
};
use crate::service::key::dto::KeyGenerateCSRRequestSubjectDTO;

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Params {
    pub payload: PayloadParams,
    pub revocation_method: Option<RevocationMethodId>,
}

#[serde_as]
#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PayloadParams {
    #[serde_as(as = "DurationSeconds<i64>")]
    pub max_validity_duration: Duration,
    #[serde(default)]
    pub allow_ca_signing: bool,
    pub path_len_constraint: Option<u8>,
    pub key_id_derivation: Option<KeyIdDerivation>,
}

// follows naming: https://www.iana.org/assignments/named-information/named-information.xhtml#hash-alg
#[derive(Debug, Clone, Deserialize)]
pub enum KeyIdDerivation {
    #[serde(rename = "sha-1")]
    Sha1,
    #[serde(rename = "sha-256")]
    Sha256,
    #[serde(rename = "sha-384")]
    Sha384,
    #[serde(rename = "sha-512")]
    Sha512,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum RequestData {
    Csr(String),
    SelfSigned(SelfSignedRequest),
}

#[derive(Debug, Serialize, Deserialize, From)]
#[from(CreateSelfSignedCertificateAuthorityContentRequestDTO)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SelfSignedRequest {
    pub subject: SubjectRequest,
    #[from(with_fn = convert_inner)]
    pub issuer_alternative_name: Option<IssuerAlternativeNameRequest>,
}

#[derive(Debug, Clone, Serialize, Deserialize, From, Into)]
#[into(CsrRequestSubject)]
#[from(KeyGenerateCSRRequestSubjectDTO)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SubjectRequest {
    pub country_name: Option<String>,
    pub common_name: Option<String>,
    pub state_or_province_name: Option<String>,
    pub organisation_name: Option<String>,
    pub locality_name: Option<String>,
    pub serial_number: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, From)]
#[from(CreateSelfSignedCertificateAuthorityIssuerAlternativeNameRequest)]
#[serde(rename_all = "camelCase")]
pub struct IssuerAlternativeNameRequest {
    pub r#type: IssuerAlternativeNameType,
    pub name: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, From)]
#[from(CreateSelfSignedCertificateAuthorityIssuerAlternativeNameType)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IssuerAlternativeNameType {
    Email,
    Uri,
}
