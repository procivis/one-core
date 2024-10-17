use one_core::provider::credential_formatter::json_ld::model::{LdCredential, LdPresentation};
use one_core::provider::did_method::model::DidDocument;
use one_core::service::vc_api::dto::{
    CredentialIssueOptions, CredentialIssueRequest, CredentialIssueResponse,
    CredentialVerifiyRequest, CredentialVerifyResponse, PresentationVerifyRequest,
    PresentationVerifyResponse, VerifyOptions,
};
use one_dto_mapper::{convert_inner, From, Into};
use serde::{Deserialize, Serialize};

use super::error::DidResolverError;
use crate::endpoint::ssi::dto::DidDocumentRestDTO;

#[derive(Debug, Serialize, Deserialize, Into)]
#[serde(rename_all = "camelCase")]
#[into(CredentialIssueRequest)]
pub struct CredentialIssueRequestDTO {
    pub credential: LdCredential,
    pub options: IssueOptionsDTO,
}

#[derive(Debug, Serialize, Deserialize, Default, Into)]
#[into(CredentialIssueOptions)]
#[serde(rename_all = "camelCase")]
pub struct IssueOptionsDTO {
    pub signature_algorithm: String,
    pub credential_format: String,
    pub revocation_method: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, From)]
#[serde(rename_all = "camelCase")]
#[from(CredentialIssueResponse)]
pub struct CredentialIssueResponseDTO {
    #[serde(flatten)]
    pub verifiable_credential: LdCredential,
}

#[derive(Debug, Serialize, Deserialize, Into)]
#[serde(rename_all = "camelCase")]
#[into(CredentialVerifiyRequest)]
pub struct CredentialVerifyRequestDTO {
    pub verifiable_credential: LdCredential,
    pub options: VerifyOptionsDTO,
}

#[derive(Debug, Serialize, Deserialize, Default, Into)]
#[serde(rename_all = "camelCase")]
#[into(VerifyOptions)]
pub struct VerifyOptionsDTO {
    #[into(with_fn = convert_inner)]
    pub checks: Vec<String>,
    pub credential_format: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, From)]
#[serde(rename_all = "camelCase")]
#[from(CredentialVerifyResponse)]
pub struct CredentialVerifyResponseDTO {
    pub checks: Vec<String>,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
    pub credential: LdCredential,
}

#[derive(Debug, Serialize, Deserialize, Into)]
#[serde(rename_all = "camelCase")]
#[into(PresentationVerifyRequest)]
pub struct PresentationVerifyRequestDTO {
    pub verifiable_presentation: LdPresentation,
    pub options: VerifyOptionsDTO,
}

#[derive(Debug, Serialize, Deserialize, From)]
#[serde(rename_all = "camelCase")]
#[from(PresentationVerifyResponse)]
pub struct PresentationVerifyResponseDTO {
    pub checks: Vec<String>,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IdentifierResponseDTO {
    pub result: VcApiDidDocumentRestDTO,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
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
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DidDocumentResolutionResponseDTO {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    pub did_document: VcApiDidDocumentRestDTO,
    pub did_document_metadata: Option<DidResolutionMetadataResponseDTO>,
    pub did_resolution_metadata: Option<DidResolutionMetadataResponseDTO>,
}

#[derive(Serialize)]
pub struct DidResolutionMetadataResponseDTO {
    pub(crate) content_type: String,
    pub(crate) error: Option<DidResolverError>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DidDocumentMetadataRestDTO {}

impl From<DidDocument> for DidDocumentResolutionResponseDTO {
    fn from(value: DidDocument) -> Self {
        Self {
            did_document: value.into(),
            context: vec!["https://w3id.org/did-resolution/v1".to_string()],
            did_document_metadata: None,
            did_resolution_metadata: Some(DidResolutionMetadataResponseDTO {
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
            did_resolution_metadata: Some(DidResolutionMetadataResponseDTO {
                content_type: "application/did+ld+json".to_string(),
                error: Some(error),
            }),
        }
    }
}
