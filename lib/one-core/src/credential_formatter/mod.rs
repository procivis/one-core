use std::collections::HashMap;

use crate::data_layer::data_model::DetailCredentialResponse;

// Implementations
pub mod jwt_formatter;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use time::OffsetDateTime;

#[derive(Debug, PartialEq, Eq, Error)]
pub enum FormatterError {
    #[error("Failed: `{0}`")]
    Failed(String),
    #[error("Could not sign: `{0}`")]
    CouldNotSign(String),
    #[error("Could not format: `{0}`")]
    CouldNotFormat(String),
    #[error("Could not extract credentials: `{0}`")]
    CouldNotExtractCredentials(String),
    #[error("Could not extract presentation: `{0}`")]
    CouldNotExtractPresentation(String),
    #[error("Incorrect signature")]
    IncorrectSignature,
}

#[derive(Debug, PartialEq, Eq, Error)]
pub enum ParseError {
    #[error("Failed: `{0}`")]
    Failed(String),
}

pub struct DetailCredential {
    pub id: Option<String>,
    pub issued_at: Option<OffsetDateTime>,
    pub expires_at: Option<OffsetDateTime>,
    pub invalid_before: Option<OffsetDateTime>,
    pub issuer_did: Option<String>,
    pub subject: Option<String>,
    pub claims: CredentialSubject,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VCCredentialClaimSchemaResponse {
    pub key: String,
    pub id: String,
    pub datatype: String,
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

pub struct CredentialPresentation {
    pub id: Option<String>,
    pub issued_at: Option<OffsetDateTime>,
    pub expires_at: Option<OffsetDateTime>,
    pub issuer_did: Option<String>,
    pub credentials: Vec<String>,
}

// This is just a proposition.
// Will be  developed in future.
pub trait CredentialFormatter {
    fn format_credentials(
        &self,
        credentials: &DetailCredentialResponse,
        holder_did: &str,
    ) -> Result<String, FormatterError>;

    fn extract_credentials(&self, credentials: &str) -> Result<DetailCredential, FormatterError>;

    fn format_presentation(
        &self,
        credentials: &[String],
        holder_did: &str,
    ) -> Result<String, FormatterError>;

    fn extract_presentation(
        &self,
        presentation: &str,
    ) -> Result<CredentialPresentation, FormatterError>;
}
