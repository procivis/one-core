use dto_mapper::Into;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    model::proof_schema::ProofSchemaClaim,
    provider::{
        credential_formatter::model::DetailCredential,
        transport_protocol::dto::SubmitIssuerResponse,
    },
};

#[derive(Clone, Debug, Deserialize)]
pub struct OpenID4VCIIssuerMetadataResponseDTO {
    pub credential_issuer: String,
    pub credential_endpoint: String,
    pub credentials_supported: Vec<OpenID4VCIIssuerMetadataCredentialSupportedResponseDTO>,
}
#[derive(Clone, Debug, Deserialize)]
pub struct OpenID4VCIIssuerMetadataCredentialSupportedResponseDTO {
    pub format: String,
    pub credential_definition: OpenID4VCIIssuerMetadataCredentialDefinitionResponseDTO,
    pub display: Option<Vec<OpenID4VCIIssuerMetadataCredentialSupportedDisplayDTO>>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct OpenID4VCIIssuerMetadataCredentialSupportedDisplayDTO {
    pub name: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct OpenID4VCIIssuerMetadataCredentialDefinitionResponseDTO {
    pub r#type: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct OpenID4VCIDiscoveryResponseDTO {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    pub response_types_supported: Vec<String>,
    pub grant_types_supported: Vec<String>,
    pub subject_types_supported: Vec<String>,
    pub id_token_signing_alg_values_supported: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(transparent)]
pub struct DurationSeconds(pub i64);

#[derive(Debug, Deserialize)]
pub struct OpenID4VCITokenResponseDTO {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: DurationSeconds,
}

#[derive(Clone, Debug)]
pub struct OpenID4VCIErrorResponseDTO {
    pub error: OpenID4VCIError,
}

#[derive(Clone, Debug, Serialize)]
pub struct OpenID4VCITokenRequestDTO {
    pub grant_type: String,
    #[serde(rename = "pre-authorized_code")]
    pub pre_authorized_code: String,
}

#[derive(Clone, Debug, PartialEq, Error)]
pub enum OpenID4VCIError {
    #[error("unsupported_grant_type")]
    UnsupportedGrantType,
    #[error("invalid_grant")]
    InvalidGrant,
    #[error("invalid_request")]
    InvalidRequest,
    #[error("invalid_token")]
    InvalidToken,
    #[error("invalid_or_missing_proof")]
    InvalidOrMissingProof,
    #[error("unsupported_credential_format")]
    UnsupportedCredentialFormat,
    #[error("unsupported_credential_type")]
    UnsupportedCredentialType,
    #[error("vp_formats_not_supported")]
    VPFormatsNotSupported,
    #[error("vc_formats_not_supported")]
    VCFormatsNotSupported,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OpenID4VCIInteractionDataDTO {
    pub pre_authorized_code_used: bool,
    pub access_token: String,
    #[serde(with = "time::serde::rfc3339::option")]
    pub access_token_expires_at: Option<OffsetDateTime>,
}

#[derive(Clone, Debug, Deserialize, Into)]
#[into(SubmitIssuerResponse)]
#[serde(rename_all = "camelCase")]
pub struct OpenID4VCICredentialResponseDTO {
    pub credential: String,
    pub format: String,
    pub redirect_uri: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct OpenID4VCICredentialDefinitionRequestDTO {
    pub r#type: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct OpenID4VCICredentialRequestDTO {
    pub format: String,
    pub credential_definition: OpenID4VCICredentialDefinitionRequestDTO,
    pub proof: OpenID4VCIProofRequestDTO,
}

#[derive(Clone, Debug, Serialize)]
pub struct OpenID4VCIProofRequestDTO {
    pub proof_type: String,
    pub jwt: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OpenID4VPDirectPostRequestDTO {
    pub presentation_submission: PresentationSubmissionMappingDTO,
    pub vp_token: String,
    pub state: Uuid,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PresentationSubmissionMappingDTO {
    pub id: String,
    pub definition_id: String,
    pub descriptor_map: Vec<PresentationSubmissionDescriptorDTO>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PresentationSubmissionDescriptorDTO {
    pub id: String,
    pub format: String,
    pub path: String,
    pub path_nested: Option<NestedPresentationSubmissionDescriptorDTO>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NestedPresentationSubmissionDescriptorDTO {
    pub format: String,
    pub path: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OpenID4VPDirectPostResponseDTO {
    pub redirect_uri: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum PresentationToken {
    One(String),
    Multiple(Vec<String>),
}

#[derive(Clone, Debug)]
pub(super) struct ValidatedProofClaimDTO {
    pub claim_schema: ProofSchemaClaim,
    pub credential: DetailCredential,
    pub value: String,
}
