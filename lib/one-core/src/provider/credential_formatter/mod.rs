pub mod error;
pub mod model;

// Implementations
pub mod jwt;

pub mod jwt_formatter;
pub mod sdjwt_formatter;

pub mod json_ld;
pub mod json_ld_bbsplus;
pub mod json_ld_classic;
pub mod mdoc_formatter;
pub mod status_list_jwt_formatter;

pub(crate) mod provider;

#[cfg(test)]
pub(crate) mod test_utilities;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use shared_types::DidValue;
use strum::Display;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::{
    crypto::signer::error::SignerError,
    service::{credential::dto::CredentialDetailResponseDTO, error::ServiceError},
};

use self::{
    error::FormatterError,
    model::{CredentialPresentation, CredentialStatus, DetailCredential, Presentation},
};

pub type AuthenticationFn = Box<dyn SignatureProvider>;
pub type VerificationFn = Box<dyn TokenVerifier>;

pub struct CredentialData {
    // URI
    pub id: String,
    pub issuance_date: OffsetDateTime,
    pub valid_for: Duration,
    pub claims: Vec<(String, String)>,
    pub issuer_did: DidValue,
    pub credential_schema: Option<CredentialSchemaData>,
    pub credential_status: Vec<CredentialStatus>,
}

pub struct CredentialSchemaData {
    pub id: Uuid,
    pub name: String,
}

#[derive(Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FormatterCapabilities {
    pub signing_key_algorithms: Vec<String>,
    pub features: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Display)]
pub enum Context {
    #[serde(rename = "https://www.w3.org/2018/credentials/v1")]
    #[strum(to_string = "https://www.w3.org/2018/credentials/v1")]
    CredentialsV1,

    #[serde(rename = "https://w3c.github.io/vc-bitstring-status-list/contexts/v1.jsonld")]
    #[strum(to_string = "https://w3c.github.io/vc-bitstring-status-list/contexts/v1.jsonld")]
    BitstringStatusList,

    #[serde(rename = "https://w3id.org/security/data-integrity/v2")]
    #[strum(to_string = "https://w3id.org/security/data-integrity/v2")]
    DataIntegrityV2,
}

#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait TokenVerifier: Send + Sync {
    async fn verify<'a>(
        &self,
        issuer_did_value: Option<DidValue>,
        issuer_key_id: Option<&'a str>,
        algorithm: &'a str,
        token: &'a [u8],
        signature: &'a [u8],
    ) -> Result<(), SignerError>;
}

#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait SignatureProvider: Send + Sync {
    async fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SignerError>;
}

#[allow(clippy::too_many_arguments)]
#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait CredentialFormatter: Send + Sync {
    async fn format_credentials(
        &self,
        credential: CredentialData,
        holder_did: &DidValue,
        algorithm: &str,
        additional_context: Vec<String>,
        additional_types: Vec<String>,
        auth_fn: AuthenticationFn,
    ) -> Result<String, FormatterError>;

    async fn extract_credentials(
        &self,
        credentials: &str,
        verification: Box<dyn TokenVerifier>,
    ) -> Result<DetailCredential, FormatterError>;

    async fn format_credential_presentation(
        &self,
        credential: CredentialPresentation,
    ) -> Result<String, FormatterError>;

    async fn extract_credentials_unverified(
        &self,
        credential: &str,
    ) -> Result<DetailCredential, FormatterError>;

    async fn format_presentation(
        &self,
        tokens: &[String],
        holder_did: &DidValue,
        algorithm: &str,
        auth_fn: AuthenticationFn,
        nonce: Option<String>,
    ) -> Result<String, FormatterError>;

    async fn extract_presentation(
        &self,
        token: &str,
        verification: Box<dyn TokenVerifier>,
    ) -> Result<Presentation, FormatterError>;

    async fn extract_presentation_unverified(
        &self,
        token: &str,
    ) -> Result<Presentation, FormatterError>;

    fn get_leeway(&self) -> u64;

    fn get_capabilities(&self) -> FormatterCapabilities;
}

#[cfg(test)]
#[derive(Clone)]
pub(crate) struct MockAuth<F: Fn(&[u8]) -> Vec<u8> + Send + Sync>(pub F);
#[cfg(test)]
#[async_trait::async_trait]
impl<F: Fn(&[u8]) -> Vec<u8> + Send + Sync> SignatureProvider for MockAuth<F> {
    async fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SignerError> {
        Ok(self.0(message))
    }
}

impl CredentialData {
    pub fn from_credential_detail_response(
        credential: CredentialDetailResponseDTO,
        core_base_url: &str,
        credential_status: Vec<CredentialStatus>,
    ) -> Result<Self, ServiceError> {
        let id = format!("{core_base_url}/ssi/credential/v1/{}", credential.id);
        let issuer_did = credential.issuer_did.map(|did| did.did).ok_or_else(|| {
            ServiceError::MappingError(format!(
                "Missing issuer DID in CredentialDetailResponseDTO for credential {id}"
            ))
        })?;

        let issuance_date = OffsetDateTime::now_utc();
        let valid_for = time::Duration::days(365 * 2);

        Ok(Self {
            id,
            issuance_date,
            valid_for,
            claims: credential
                .claims
                .into_iter()
                .map(|claim| (claim.schema.key, claim.value))
                .collect(),
            issuer_did,
            credential_schema: Some(CredentialSchemaData {
                id: credential.schema.id,
                name: credential.schema.name,
            }),
            credential_status,
        })
    }
}
