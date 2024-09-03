use dto_mapper::{convert_inner, From, Into};
use one_core::service::vc_api::dto::{
    CredentialIssueOptions, CredentialIssueRequest, CredentialIssueResponse,
    CredentialVerifiyRequest, CredentialVerifyResponse, PresentationVerifyRequest,
    PresentationVerifyResponse, VerifyOptions,
};
use one_providers::credential_formatter::imp::json_ld::model::{LdCredential, LdPresentation};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Debug, Serialize, Deserialize, Into)]
#[serde(rename_all = "camelCase")]
#[into(CredentialIssueRequest)]
pub struct CredentialIssueRequestDto {
    pub credential: LdCredential,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[into(with_fn = convert_inner)]
    pub options: Option<IssueOptionsDto>,
}

#[derive(Debug, Serialize, Deserialize, Default, Into)]
#[into(CredentialIssueOptions)]
#[serde(rename_all = "camelCase")]
pub struct IssueOptionsDto {
    pub signature_algorithm: String,
    pub credential_format: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(CredentialIssueResponse)]
pub struct CredentialIssueResponseDto {
    #[serde(flatten)]
    pub verifiable_credential: LdCredential,
}

#[derive(Debug, Serialize, Deserialize, Into)]
#[serde(rename_all = "camelCase")]
#[into(CredentialVerifiyRequest)]
pub struct CredentialVerifiyRequestDto {
    pub verifiable_credential: LdCredential,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[into(with_fn = convert_inner)]
    pub options: Option<VerifyOptionsDto>,
}

#[derive(Debug, Serialize, Deserialize, Default, Into)]
#[serde(rename_all = "camelCase")]
#[into(VerifyOptions)]
pub struct VerifyOptionsDto {
    #[into(with_fn = convert_inner)]
    pub checks: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(CredentialVerifyResponse)]
pub struct CredentialVerifyResponseDto {
    pub checks: Vec<String>,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
    pub credential: LdCredential,
}

#[derive(Debug, Serialize, Deserialize, ToSchema, Into)]
#[serde(rename_all = "camelCase")]
#[into(PresentationVerifyRequest)]
pub struct PresentationVerifyRequestDto {
    pub verifiable_presentation: LdPresentation,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[into(with_fn = convert_inner)]
    pub options: Option<VerifyOptionsDto>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(PresentationVerifyResponse)]
pub struct PresentationVerifyResponseDto {
    pub checks: Vec<String>,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
}
