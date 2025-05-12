use std::collections::HashMap;

use indexmap::IndexSet;
use serde::{Deserialize, Deserializer, Serialize};
use serde_with::{OneOrMany, serde_as, skip_serializing_none};
use shared_types::DidValue;
use time::OffsetDateTime;
use url::Url;

use crate::provider::credential_formatter::model::{
    CredentialSchema, CredentialStatus, Description, Issuer, Name,
};
use crate::provider::credential_formatter::vcdm::{ContextType, VcdmProof};

pub type VerifiableCredential = Vec<serde_json::Map<String, serde_json::Value>>;

pub static DEFAULT_ALLOWED_CONTEXTS: [&str; 4] = [
    "https://www.w3.org/ns/credentials/v2",
    "https://www.w3.org/2018/credentials/v1",
    "https://w3c.github.io/vc-bitstring-status-list/contexts/v1.jsonld",
    "https://w3id.org/security/data-integrity/v2",
];

// The main credential
#[skip_serializing_none]
#[serde_as]
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct LdCredential {
    #[serde(rename = "@context")]
    pub context: IndexSet<ContextType>,

    #[serde(default, deserialize_with = "deserialize_option_or_error_if_null")]
    pub id: Option<Url>,

    pub r#type: Vec<String>,
    pub issuer: Issuer,
    // we keep this field for backwards compatibility with VCDM v1.1
    #[serde(with = "time::serde::rfc3339::option")]
    #[serde(default)]
    pub issuance_date: Option<OffsetDateTime>,

    #[serde(with = "time::serde::rfc3339::option")]
    #[serde(default)]
    pub valid_from: Option<OffsetDateTime>,

    #[serde(with = "time::serde::rfc3339::option")]
    #[serde(default)]
    pub valid_until: Option<OffsetDateTime>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[serde_as(as = "OneOrMany<_>")]
    pub credential_subject: Vec<LdCredentialSubject>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[serde_as(as = "OneOrMany<_>")]
    pub credential_status: Vec<CredentialStatus>,

    pub proof: Option<LdProof>,

    #[serde_as(as = "Option<OneOrMany<_>>")]
    pub credential_schema: Option<Vec<CredentialSchema>>,

    #[serde(default)]
    #[serde_as(as = "Option<OneOrMany<_>>")]
    pub refresh_service: Option<Vec<LdRefreshService>>,

    #[serde(default)]
    pub name: Option<Name>,

    #[serde(default)]
    pub description: Option<Description>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[serde_as(as = "OneOrMany<_>")]
    pub terms_of_use: Vec<TermsOfUse>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[serde_as(as = "OneOrMany<_>")]
    pub evidence: Vec<Evidence>,

    #[serde(default)]
    #[serde_as(as = "Option<OneOrMany<_>>")]
    pub related_resource: Option<Vec<RelatedResource>>,
}

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LdRefreshService {
    #[serde_as(as = "OneOrMany<_>")]
    r#type: Vec<String>,
    // Which fields will be present depends on the `type`
    #[serde(flatten)]
    fields: serde_json::Map<String, serde_json::Value>,
}

#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LdCredentialSubject {
    pub id: Option<DidValue>,
    #[serde(flatten)]
    pub subject: HashMap<String, serde_json::Value>,
}

pub type Claims = HashMap<String, String>;

#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LdProof {
    #[serde(rename = "@context")]
    pub context: Option<IndexSet<ContextType>>,
    pub r#type: String,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub created: Option<OffsetDateTime>,
    pub cryptosuite: String,
    pub verification_method: String,
    pub proof_purpose: String,
    pub proof_value: Option<String>,
    pub nonce: Option<String>,
    pub challenge: Option<String>,
    pub domain: Option<String>,
}

// The main presentation
#[skip_serializing_none]
#[serde_as]
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct LdPresentation {
    #[serde(rename = "@context")]
    pub context: IndexSet<ContextType>,

    #[serde_as(as = "OneOrMany<_>")]
    pub r#type: Vec<String>,

    pub verifiable_credential: VerifiableCredential,
    pub holder: Issuer,

    pub proof: Option<VcdmProof>,
}

#[skip_serializing_none]
#[serde_as]
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct TermsOfUse {
    #[serde_as(as = "OneOrMany<_>")]
    r#type: Vec<String>,

    #[serde(default, deserialize_with = "deserialize_option_or_error_if_null")]
    id: Option<Url>,
}

#[skip_serializing_none]
#[serde_as]
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Evidence {
    #[serde_as(as = "OneOrMany<_>")]
    r#type: Vec<String>,

    #[serde(default, deserialize_with = "deserialize_option_or_error_if_null")]
    id: Option<Url>,
}

#[skip_serializing_none]
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct RelatedResource {
    pub id: Url,
    pub media_type: Option<String>,
    #[serde(rename = "digestSRI")]
    pub digest_sri: Option<String>,
    pub digest_multibase: Option<String>,
}

fn deserialize_option_or_error_if_null<'de, D>(deserializer: D) -> Result<Option<Url>, D::Error>
where
    D: Deserializer<'de>,
{
    match Option::<Url>::deserialize(deserializer)? {
        Some(url) => Ok(Some(url)),
        None => Err(serde::de::Error::custom(
            "Deserializer forbids deserializing null as an Option::None",
        )),
    }
}
