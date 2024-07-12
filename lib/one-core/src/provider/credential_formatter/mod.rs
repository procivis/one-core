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
pub mod physical_card;
pub mod status_list_jwt_formatter;

pub(crate) mod provider;

#[cfg(test)]
mod test;
#[cfg(test)]
pub(crate) mod test_utilities;

use one_providers::crypto::SignerError;
use std::collections::HashMap;
use std::fmt::{Display, Formatter};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use shared_types::DidValue;
use strum::Display;
use time::{Duration, OffsetDateTime};
use url::Url;

use self::error::FormatterError;
use self::model::{
    CredentialPresentation, CredentialSchema, CredentialStatus, DetailCredential, Presentation,
};
use super::exchange_protocol::openid4vc::dto::OpenID4VPInteractionData;
use crate::config::core_config::{CoreConfig, DatatypeType};
use crate::model::credential_schema::CredentialSchemaType;
use crate::service::credential::dto::{
    CredentialDetailResponseDTO, DetailCredentialClaimResponseDTO,
    DetailCredentialClaimValueResponseDTO,
};
use crate::service::error::ServiceError;
use crate::service::oidc::model::OpenID4VPInteractionContent;

pub type AuthenticationFn = Box<dyn SignatureProvider>;
pub type VerificationFn = Box<dyn TokenVerifier>;

#[derive(Clone, Debug, PartialEq)]
pub struct PublishedClaim {
    pub key: String,
    pub value: PublishedClaimValue,
    pub datatype: Option<String>,
    pub array_item: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub enum PublishedClaimValue {
    Bool(bool),
    Float(f64),
    Integer(i64),
    String(String),
}

impl TryFrom<PublishedClaimValue> for serde_json::Value {
    type Error = FormatterError;

    fn try_from(value: PublishedClaimValue) -> Result<Self, Self::Error> {
        Ok(match value {
            PublishedClaimValue::Bool(value) => serde_json::Value::Bool(value),
            PublishedClaimValue::Float(value) => serde_json::Value::Number(
                serde_json::Number::from_f64(value).ok_or(FormatterError::FloatValueIsNaN)?,
            ),
            PublishedClaimValue::Integer(value) => {
                serde_json::Value::Number(serde_json::Number::from(value))
            }
            PublishedClaimValue::String(value) => serde_json::Value::String(value),
        })
    }
}

impl Display for PublishedClaimValue {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            PublishedClaimValue::Bool(value) => write!(f, "{}", value),
            PublishedClaimValue::Float(value) => write!(f, "{}", value),
            PublishedClaimValue::Integer(value) => write!(f, "{}", value),
            PublishedClaimValue::String(value) => write!(f, "{}", value),
        }
    }
}

impl From<&str> for PublishedClaimValue {
    fn from(value: &str) -> Self {
        PublishedClaimValue::String(value.to_string())
    }
}

impl PartialEq<str> for PublishedClaimValue {
    fn eq(&self, other: &str) -> bool {
        if let PublishedClaimValue::String(value) = self {
            value == other
        } else {
            false
        }
    }
}

#[derive(Debug)]
pub struct CredentialData {
    // URI
    pub id: String,
    pub issuance_date: OffsetDateTime,
    pub valid_for: Duration,
    pub claims: Vec<PublishedClaim>,
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
    pub selective_disclosure: Vec<SelectiveDisclosureOption>,
    pub issuance_did_methods: Vec<String>,
    pub issuance_exchange_protocols: Vec<String>,
    pub proof_exchange_protocols: Vec<String>,
    pub revocation_methods: Vec<String>,
    pub signing_key_algorithms: Vec<String>,
    pub verification_key_algorithms: Vec<String>,
    pub datatypes: Vec<String>,
    pub allowed_schema_ids: Vec<String>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SelectiveDisclosureOption {
    AnyLevel,
    SecondLevel,
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
    fn get_key_id(&self) -> Option<String>;
    fn get_public_key(&self) -> Vec<u8>;
}

#[derive(Debug, Default, Clone)]
pub struct ExtractPresentationCtx {
    nonce: Option<String>,
    mdoc_generated_nonce: Option<String>,
    issuance_date: Option<OffsetDateTime>,
    expiration_date: Option<OffsetDateTime>,
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
}

impl From<OpenID4VPInteractionContent> for ExtractPresentationCtx {
    fn from(data: OpenID4VPInteractionContent) -> Self {
        Self {
            nonce: Some(data.nonce),
            mdoc_generated_nonce: None,
            issuance_date: None,
            expiration_date: None,
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
    fn get_key_id(&self) -> Option<String> {
        Some("#key0".to_owned())
    }
    fn get_public_key(&self) -> Vec<u8> {
        vec![]
    }
}

impl CredentialData {
    pub fn from_credential_detail_response(
        config: &CoreConfig,
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

        let mut array_order: HashMap<String, usize> = HashMap::new();

        Ok(Self {
            id,
            issuance_date,
            valid_for,
            claims: map_claims(
                config,
                &credential.claims,
                &mut array_order,
                "",
                false,
                false,
            ),
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

fn map_claims(
    config: &CoreConfig,
    claims: &[DetailCredentialClaimResponseDTO],
    array_order: &mut HashMap<String, usize>,
    prefix: &str,
    array_item: bool,
    object_item: bool,
) -> Vec<PublishedClaim> {
    let mut result = vec![];

    for claim in claims {
        let published_claim_value = match &claim.value {
            DetailCredentialClaimValueResponseDTO::Nested(value) => {
                let key = if array_item {
                    let array_index = array_order.entry(prefix.to_string()).or_default();
                    let current_index = array_index.to_owned();
                    *array_index += 1;
                    current_index.to_string()
                } else {
                    claim.schema.key.clone()
                };

                let is_object = config
                    .get_datatypes_of_type(DatatypeType::Object)
                    .contains(&claim.schema.datatype.as_str());

                let nested_claims = map_claims(
                    config,
                    value,
                    array_order,
                    &format!("{prefix}{key}/"),
                    claim.schema.array,
                    is_object,
                );
                result.extend(nested_claims);

                None
            }
            DetailCredentialClaimValueResponseDTO::String(value) => {
                Some(PublishedClaimValue::String(value.to_owned()))
            }
            DetailCredentialClaimValueResponseDTO::Boolean(value) => {
                Some(PublishedClaimValue::Bool(value.to_owned()))
            }
            DetailCredentialClaimValueResponseDTO::Float(value) => {
                Some(PublishedClaimValue::Float(value.to_owned()))
            }
            DetailCredentialClaimValueResponseDTO::Integer(value) => {
                Some(PublishedClaimValue::Integer(value.to_owned()))
            }
        };

        let key = if array_item && !object_item {
            claim.path.clone()
        } else {
            format!("{prefix}{}", claim.schema.key.clone())
        };

        if let Some(value) = published_claim_value {
            result.push(PublishedClaim {
                key,
                value,
                datatype: Some(claim.clone().schema.datatype),
                array_item,
            });
        }
    }

    result
}
