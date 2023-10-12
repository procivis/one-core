use std::collections::HashMap;

// Implementations
pub mod jwt_formatter;
pub(crate) mod provider;
pub mod sdjwt;

use crate::{crypto::signer::SignerError, service::credential::dto::CredentialDetailResponseDTO};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use time::OffsetDateTime;

#[derive(Debug, PartialEq, Eq, Error)]
pub enum FormatterError {
    #[error("Failed: `{0}`")]
    Failed(String),
    #[error("Could not sign: `{0}`")]
    CouldNotSign(String),
    #[error("Could not verify: `{0}`")]
    CouldNotVerify(String),
    #[error("Could not format: `{0}`")]
    CouldNotFormat(String),
    #[error("Could not extract credentials: `{0}`")]
    CouldNotExtractCredentials(String),
    #[error("Could not extract presentation: `{0}`")]
    CouldNotExtractPresentation(String),
    #[error("Could not extract claims from presentation: `{0}`")]
    CouldNotExtractClaimsFromPresentation(String),
    #[error("Incorrect signature")]
    IncorrectSignature,
    #[error("Missing signer")]
    MissingSigner,
    #[error("Missing hasher")]
    MissingHasher,
    #[error("Missing part")]
    MissingPart,
    #[error("Missing disclosure")]
    MissingDisclosure,
    #[error("Missing claim")]
    MissingClaim,
    #[error("Signer error `{0}`")]
    SignerError(#[from] SignerError),
}

#[derive(Debug, PartialEq, Eq, Error)]
pub enum ParseError {
    #[error("Failed: `{0}`")]
    Failed(String),
}

#[derive(Debug)]
pub struct DetailCredential {
    pub id: Option<String>,
    pub issued_at: Option<OffsetDateTime>,
    pub expires_at: Option<OffsetDateTime>,
    pub invalid_before: Option<OffsetDateTime>,
    pub issuer_did: Option<String>,
    pub subject: Option<String>,
    pub claims: CredentialSubject,
    pub status: Option<CredentialStatus>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VCCredentialClaimSchemaResponse {
    pub key: String,
    pub id: String,
    pub datatype: String,
    pub required: bool,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VCCredentialSchemaResponse {
    pub name: String,
    pub id: String,
    pub claims: Vec<VCCredentialClaimSchemaResponse>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialSubject {
    #[serde(flatten)]
    pub values: HashMap<String, String>,
    pub one_credential_schema: VCCredentialSchemaResponse,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CredentialPresentation {
    pub id: Option<String>,
    pub issued_at: Option<OffsetDateTime>,
    pub expires_at: Option<OffsetDateTime>,
    pub issuer_did: Option<String>,
    pub credentials: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PresentationCredential {
    pub token: String,
    pub disclosed_keys: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialStatus {
    pub id: String,
    pub r#type: String,
    pub status_purpose: String,
    #[serde(flatten)]
    pub additional_fields: HashMap<String, String>,
}

pub trait CredentialFormatter {
    fn format_credentials(
        &self,
        credential: &CredentialDetailResponseDTO,
        credential_status: Option<CredentialStatus>,
        holder_did: &str,
        algorithm: &str,
        additional_context: Vec<String>,
        additional_types: Vec<String>,
    ) -> Result<String, FormatterError>;

    fn extract_credentials(&self, credentials: &str) -> Result<DetailCredential, FormatterError>;

    fn format_presentation(
        &self,
        tokens: &[PresentationCredential],
        holder_did: &str,
        algorithm: &str,
    ) -> Result<String, FormatterError>;

    fn extract_presentation(&self, token: &str) -> Result<CredentialPresentation, FormatterError>;
}
