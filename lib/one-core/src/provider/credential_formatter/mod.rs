pub mod error;
pub mod model;

mod common;

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
mod test;
#[cfg(test)]
pub(crate) mod test_utilities;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use shared_types::DidValue;
use strum::Display;
use time::{Duration, OffsetDateTime};
use url::Url;

use crate::{
    crypto::signer::error::SignerError,
    model::credential_schema::CredentialSchemaType,
    service::{
        credential::dto::{
            CredentialDetailResponseDTO, DetailCredentialClaimResponseDTO,
            DetailCredentialClaimValueResponseDTO,
        },
        error::ServiceError,
    },
};

use self::{
    error::FormatterError,
    model::{
        CredentialPresentation, CredentialSchema, CredentialStatus, DetailCredential, Presentation,
    },
};

use super::transport_protocol::openid4vc::dto::OpenID4VPInteractionData;
use crate::service::oidc::model::OpenID4VPInteractionContent;

pub type AuthenticationFn = Box<dyn SignatureProvider>;
pub type VerificationFn = Box<dyn TokenVerifier>;

#[derive(Debug)]
pub struct CredentialData {
    // URI
    pub id: String,
    pub issuance_date: OffsetDateTime,
    pub valid_for: Duration,
    pub claims: Vec<(String, String)>,
    pub issuer_did: DidValue,
    pub status: Vec<CredentialStatus>,
    pub schema: CredentialSchemaData,
}

#[derive(Debug)]
pub struct CredentialSchemaData {
    // todo: use an URI type
    pub id: Option<String>,
    pub r#type: Option<CredentialSchemaType>,
    pub context: Option<String>,
    pub name: String,
}

impl From<CredentialSchemaData> for Option<CredentialSchema> {
    fn from(credential_schema: CredentialSchemaData) -> Self {
        match credential_schema {
            CredentialSchemaData {
                id: Some(id),
                r#type: Some(r#type),
                ..
            } => Some(CredentialSchema::new(id, r#type)),
            _ => None,
        }
    }
}

#[derive(Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FormatterCapabilities {
    pub features: Vec<String>,
    pub issuance_exchange_protocols: Vec<String>,
    pub proof_exchange_protocols: Vec<String>,
    pub revocation_methods: Vec<String>,
    pub signing_key_algorithms: Vec<String>,
    pub verification_key_algorithms: Vec<String>,
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

#[derive(Debug, Default)]
pub struct ExtractCredentialsCtx {
    pub holder_did: Option<DidValue>,
}

#[derive(Debug, Default, Clone)]
pub struct ExtractPresentationCtx {
    nonce: Option<String>,
    mdoc_generated_nonce: Option<String>,
    issuance_date: Option<OffsetDateTime>,
    expiration_date: Option<OffsetDateTime>,
    holder_did: Option<DidValue>,
}

impl ExtractPresentationCtx {
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn with_mdoc_generated_nonce(mut self, mdoc_generated_nonce: String) -> Self {
        self.mdoc_generated_nonce = Some(mdoc_generated_nonce);

        self
    }

    pub fn with_issuance_date(mut self, issuance_date: OffsetDateTime) -> Self {
        self.issuance_date = Some(issuance_date);

        self
    }

    pub fn with_expiration_date(mut self, expiration_date: OffsetDateTime) -> Self {
        self.issuance_date = Some(expiration_date);

        self
    }

    pub fn with_holder_did(mut self, holder_did: DidValue) -> Self {
        self.holder_did = Some(holder_did);

        self
    }

    pub fn get_holder_did(&self) -> Option<DidValue> {
        self.holder_did.clone()
    }
}

impl From<OpenID4VPInteractionContent> for ExtractPresentationCtx {
    fn from(data: OpenID4VPInteractionContent) -> Self {
        Self {
            nonce: Some(data.nonce),
            mdoc_generated_nonce: None,
            issuance_date: None,
            expiration_date: None,
            holder_did: None,
        }
    }
}

#[derive(Debug, Default)]
pub struct FormatPresentationCtx {
    nonce: Option<String>,
    mdoc_generated_nonce: Option<String>,
    client_id: Option<Url>,
    response_uri: Option<Url>,
}

impl FormatPresentationCtx {
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn with_nonce(mut self, nonce: String) -> Self {
        self.nonce = Some(nonce);

        self
    }

    pub fn with_mdoc_generated_nonce(mut self, mdoc_generated_nonce: String) -> Self {
        self.mdoc_generated_nonce = Some(mdoc_generated_nonce);

        self
    }
}

impl From<OpenID4VPInteractionData> for FormatPresentationCtx {
    fn from(data: OpenID4VPInteractionData) -> Self {
        Self {
            nonce: Some(data.nonce),
            client_id: Some(data.client_id),
            response_uri: Some(data.response_uri),
            mdoc_generated_nonce: None,
        }
    }
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
        json_ld_context_url: Option<String>,
        custom_subject_name: Option<String>,
    ) -> Result<String, FormatterError>;

    async fn extract_credentials(
        &self,
        credentials: &str,
        verification: Box<dyn TokenVerifier>,
        ctx: ExtractCredentialsCtx,
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
        ctx: FormatPresentationCtx,
    ) -> Result<String, FormatterError>;

    async fn extract_presentation(
        &self,
        token: &str,
        verification: Box<dyn TokenVerifier>,
        ctx: ExtractPresentationCtx,
    ) -> Result<Presentation, FormatterError>;

    async fn extract_presentation_unverified(
        &self,
        token: &str,
        ctx: ExtractPresentationCtx,
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
            claims: map_claims(&credential.claims, ""),
            issuer_did,
            status: credential_status,
            schema: CredentialSchemaData {
                id: Some(credential.schema.schema_id),
                r#type: Some(credential.schema.schema_type.into()),
                context: Some(format!(
                    "{core_base_url}/ssi/context/v1/{}",
                    credential.schema.id
                )),
                name: credential.schema.name,
            },
        })
    }
}

fn map_claims(claims: &[DetailCredentialClaimResponseDTO], prefix: &str) -> Vec<(String, String)> {
    let mut result = vec![];

    claims.iter().for_each(|claim| match &claim.value {
        DetailCredentialClaimValueResponseDTO::String(value) => {
            result.push((format!("{prefix}{}", claim.schema.key), value.to_owned()));
        }
        DetailCredentialClaimValueResponseDTO::Nested(value) => {
            let nested_claims = map_claims(value, &format!("{prefix}{}/", claim.schema.key));
            result.extend(nested_claims);
        }
    });

    result
}
