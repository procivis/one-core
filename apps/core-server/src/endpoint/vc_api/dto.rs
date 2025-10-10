use one_core::provider::credential_formatter::vcdm::VcdmCredential;
use one_core::provider::did_method::dto::DidDocumentDTO;
use one_core::provider::presentation_formatter::ldp_vp::model::LdPresentation;
use one_core::service::vc_api::dto::{
    CredentialIssueOptions, CredentialIssueRequest, CredentialIssueResponse,
    CredentialVerifiyRequest, CredentialVerifyResponse, PresentationVerifyRequest,
    PresentationVerifyResponse, VerifyOptions,
};
use one_core::service::vc_api::model::LdCredential;
use one_dto_mapper::{From, Into, convert_inner};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

use super::error::DidResolverError;
use crate::endpoint::ssi::dto::DidDocumentRestDTO;

#[derive(Debug, Deserialize, Into)]
#[serde(rename_all = "camelCase")]
#[into(CredentialIssueRequest)]
pub struct CredentialIssueRequestDTO {
    pub credential: VcdmCredential,
    pub options: IssueOptionsDTO,
}

#[skip_serializing_none]
#[derive(Debug, Deserialize, Default, Into)]
#[into(CredentialIssueOptions)]
#[serde(rename_all = "camelCase")]
pub struct IssueOptionsDTO {
    pub signature_algorithm: String,
    pub credential_format: String,
    pub revocation_method: Option<String>,
}

#[derive(Debug, Serialize, From)]
#[serde(rename_all = "camelCase")]
#[from(CredentialIssueResponse)]
pub struct CredentialIssueResponseDTO {
    #[serde(flatten)]
    pub verifiable_credential: LdCredential,
}

#[derive(Debug, Deserialize, Into)]
#[serde(rename_all = "camelCase")]
#[into(CredentialVerifiyRequest)]
pub struct CredentialVerifyRequestDTO {
    pub verifiable_credential: VcdmCredential,
    pub options: VerifyOptionsDTO,
}

#[skip_serializing_none]
#[derive(Debug, Deserialize, Default, Into)]
#[serde(rename_all = "camelCase")]
#[into(VerifyOptions)]
pub struct VerifyOptionsDTO {
    #[into(with_fn = convert_inner)]
    pub checks: Vec<String>,
    pub credential_format: Option<String>,
}

#[derive(Debug, Serialize, From)]
#[serde(rename_all = "camelCase")]
#[from(CredentialVerifyResponse)]
pub struct CredentialVerifyResponseDTO {
    pub checks: Vec<String>,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
    pub credential: VcdmCredential,
}

#[derive(Debug, Deserialize, Into)]
#[serde(rename_all = "camelCase")]
#[into(PresentationVerifyRequest)]
pub struct PresentationVerifyRequestDTO {
    pub verifiable_presentation: LdPresentation,
    pub options: VerifyOptionsDTO,
}

#[derive(Debug, Serialize, From)]
#[serde(rename_all = "camelCase")]
#[from(PresentationVerifyResponse)]
pub struct PresentationVerifyResponseDTO {
    pub checks: Vec<String>,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
}

#[skip_serializing_none]
#[derive(Debug, Serialize)]
pub struct VcApiDidDocumentRestDTO {
    pub document: Option<DidDocumentRestDTO>,
}

impl From<DidDocumentDTO> for VcApiDidDocumentRestDTO {
    fn from(value: DidDocumentDTO) -> Self {
        Self {
            document: Some(DidDocumentRestDTO::from(value)),
        }
    }
}

#[skip_serializing_none]
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DidDocumentResolutionResponseDTO {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    pub did_document: VcApiDidDocumentRestDTO,
    pub did_document_metadata: Option<DidResolutionMetadataResponseDTO>,
    pub did_resolution_metadata: Option<DidResolutionMetadataResponseDTO>,
}

#[skip_serializing_none]
#[derive(Serialize)]
pub struct DidResolutionMetadataResponseDTO {
    pub(crate) content_type: String,
    pub(crate) error: Option<DidResolverError>,
}

impl From<DidDocumentDTO> for DidDocumentResolutionResponseDTO {
    fn from(value: DidDocumentDTO) -> Self {
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
