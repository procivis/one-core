use dto_mapper::{convert_inner, From, Into};
use one_core::service::vc_api::dto::{
    CredentialIssueOptions, CredentialIssueRequest, CredentialIssueResponse,
    CredentialVerifiyRequest, CredentialVerifyResponse, PresentationVerifyRequest,
    PresentationVerifyResponse, VerifyOptions,
};
use one_providers::credential_formatter::imp::json_ld::model::{LdCredential, LdPresentation};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Debug, Serialize, Deserialize, Into, From)]
#[serde(rename_all = "camelCase")]
#[into(CredentialIssueRequest)]
#[from(CredentialIssueRequest)]
pub struct CredentialIssueRequestDto {
    pub credential: LdCredential,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[into(with_fn = convert_inner)]
    #[from(with_fn = convert_inner)]
    pub options: Option<IssueOptionsDto>,
}

#[derive(Debug, Serialize, Deserialize, Default, Into, From)]
#[into(CredentialIssueOptions)]
#[from(CredentialIssueOptions)]
#[serde(rename_all = "camelCase")]
pub struct IssueOptionsDto {
    pub issuer_id: Option<String>,
    pub r#type: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema, Into, From)]
#[serde(rename_all = "camelCase")]
#[from(CredentialIssueResponse)]
#[into(CredentialIssueResponse)]
pub struct CredentialIssueResponseDto {
    #[serde(flatten)]
    pub verifiable_credential: LdCredential,
}

#[derive(Debug, Serialize, Deserialize, Into, From)]
#[serde(rename_all = "camelCase")]
#[into(CredentialVerifiyRequest)]
#[from(CredentialVerifiyRequest)]
pub struct CredentialVerifiyRequestDto {
    pub verifiable_credential: LdCredential,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[into(with_fn = convert_inner)]
    #[from(with_fn = convert_inner)]
    pub options: Option<VerifyOptionsDto>,
}

#[derive(Debug, Serialize, Deserialize, Default, Into, From)]
#[serde(rename_all = "camelCase")]
#[into(VerifyOptions)]
#[from(VerifyOptions)]
pub struct VerifyOptionsDto {
    #[into(with_fn = convert_inner)]
    pub checks: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema, Into, From)]
#[serde(rename_all = "camelCase")]
#[into(CredentialVerifyResponse)]
#[from(CredentialVerifyResponse)]
pub struct CredentialVerifyResponseDto {
    pub checks: Vec<String>,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
    pub credential: LdCredential,
}

#[derive(Debug, Serialize, Deserialize, ToSchema, Into, From)]
#[serde(rename_all = "camelCase")]
#[into(PresentationVerifyRequest)]
#[from(PresentationVerifyRequest)]
pub struct PresentationVerifyRequestDto {
    pub verifiable_presentation: LdPresentation,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[into(with_fn = convert_inner)]
    #[from(with_fn = convert_inner)]
    pub options: Option<VerifyOptionsDto>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema, Into, From)]
#[serde(rename_all = "camelCase")]
#[into(PresentationVerifyResponse)]
#[from(PresentationVerifyResponse)]
pub struct PresentationVerifyResponseDto {
    pub checks: Vec<String>,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
}
