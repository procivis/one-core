use dto_mapper::{convert_inner, From, Into};
use one_core::service::vc_api::dto::{
    CredentialIssueOptions, CredentialIssueRequest, CredentialIssueResponse,
    CredentialVerifiyRequest, CredentialVerifyResponse, PresentationVerifyRequest,
    PresentationVerifyResponse, VerifyOptions,
};
use one_providers::credential_formatter::imp::json_ld::model::{LdCredential, LdPresentation};
use one_providers::did::model::DidDocument;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::error::DidResolverError;
use crate::endpoint::ssi::dto::DidDocumentRestDTO;

#[derive(Debug, Serialize, Deserialize, Into)]
#[serde(rename_all = "camelCase")]
#[into(CredentialIssueRequest)]
pub struct CredentialIssueRequestDto {
    pub credential: LdCredential,
    pub options: IssueOptionsDto,
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
pub struct CredentialIssueResponseDTO {
    #[serde(flatten)]
    pub verifiable_credential: LdCredential,
}

#[derive(Debug, Serialize, Deserialize, Into)]
#[serde(rename_all = "camelCase")]
#[into(CredentialVerifiyRequest)]
pub struct CredentialVerifiyRequestDto {
    pub verifiable_credential: LdCredential,
    pub options: VerifyOptionsDto,
}

#[derive(Debug, Serialize, Deserialize, Default, Into)]
#[serde(rename_all = "camelCase")]
#[into(VerifyOptions)]
pub struct VerifyOptionsDto {
    #[into(with_fn = convert_inner)]
    pub checks: Vec<String>,
    pub credential_format: Option<String>,
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
    pub options: VerifyOptionsDto,
}

#[derive(Debug, Serialize, Deserialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(PresentationVerifyResponse)]
pub struct PresentationVerifyResponseDto {
    pub checks: Vec<String>,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct IdentifierResponseDto {
    pub result: VcApiDidDocumentRestDTO,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct VcApiDidDocumentRestDTO {
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pub document: Option<DidDocumentRestDTO>,
}

impl From<DidDocument> for VcApiDidDocumentRestDTO {
    fn from(value: DidDocument) -> Self {
        Self {
            document: Some(DidDocumentRestDTO::from(value)),
        }
    }
}
#[derive(Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DidDocumentResolutionResponseDTO {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    pub did_document: VcApiDidDocumentRestDTO,
    pub did_document_metadata: Option<DidResolutionMetadataResponseDto>,
    pub did_resolution_metadata: Option<DidResolutionMetadataResponseDto>,
}

#[derive(Serialize, ToSchema)]
pub struct DidResolutionMetadataResponseDto {
    pub(crate) content_type: String,
    pub(crate) error: Option<DidResolverError>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct DidDocumentMetadataRestDTO {}

impl From<DidDocument> for DidDocumentResolutionResponseDTO {
    fn from(value: DidDocument) -> Self {
        Self {
            did_document: value.into(),
            context: vec!["https://w3id.org/did-resolution/v1".to_string()],
            did_document_metadata: None,
            did_resolution_metadata: Some(DidResolutionMetadataResponseDto {
                content_type: "application/did+ld+json".to_string(),
                error: None,
            }),
        }
    }
}

impl DidDocumentResolutionResponseDTO {
    pub fn from_error(error: DidResolverError) -> Self {
        Self {
            context: vec!["https://w3id.org/did-resolution/v1".to_string()],
            did_document: VcApiDidDocumentRestDTO { document: None },
            did_document_metadata: None,
            did_resolution_metadata: Some(DidResolutionMetadataResponseDto {
                content_type: "application/did+ld+json".to_string(),
                error: Some(error),
            }),
        }
    }
}
