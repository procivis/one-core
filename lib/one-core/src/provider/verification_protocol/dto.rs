use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use shared_types::DidValue;
use time::OffsetDateTime;

use crate::config::core_config::DidType;
use crate::model::credential::Credential;
use crate::model::credential_schema::{CredentialSchemaType, WalletStorageTypeEnum};
use crate::service::credential::dto::CredentialDetailResponseDTO;

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// deserializes matching `ConnectVerifierResponseRestDTO`
pub(crate) struct ConnectVerifierResponse {
    pub claims: Vec<ProofClaimSchema>,
    pub verifier_did: DidValue,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
/// deserializes matching `ProofRequestClaimRestDTO`
pub(crate) struct ProofClaimSchema {
    pub id: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created_date: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub last_modified: OffsetDateTime,
    pub key: String,
    pub datatype: String,
    pub required: bool,
    pub credential_schema: ProofCredentialSchema,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// deserializes matching `CredentialSchemaListValueResponseRestDTO`
pub(crate) struct ProofCredentialSchema {
    pub id: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created_date: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub last_modified: OffsetDateTime,
    pub name: String,
    pub format: String,
    pub revocation_method: String,
    pub wallet_storage_type: Option<WalletStorageTypeEnum>,
    pub schema_type: CredentialSchemaType,
    pub schema_id: String,
}

#[derive(Clone, Debug)]
pub struct PresentationDefinitionResponseDTO {
    pub request_groups: Vec<PresentationDefinitionRequestGroupResponseDTO>,
    pub credentials: Vec<CredentialDetailResponseDTO>,
}

#[derive(Clone, Debug)]
pub struct PresentationDefinitionRequestGroupResponseDTO {
    pub id: String,
    pub name: Option<String>,
    pub purpose: Option<String>,
    pub rule: PresentationDefinitionRuleDTO,
    pub requested_credentials: Vec<PresentationDefinitionRequestedCredentialResponseDTO>,
}

#[derive(Clone, Debug)]
pub struct PresentationDefinitionRequestedCredentialResponseDTO {
    pub id: String,
    pub name: Option<String>,
    pub purpose: Option<String>,
    pub fields: Vec<PresentationDefinitionFieldDTO>,
    pub applicable_credentials: Vec<String>,
    pub inapplicable_credentials: Vec<String>,
    pub validity_credential_nbf: Option<OffsetDateTime>,
}

#[derive(Clone, Debug)]
pub struct PresentationDefinitionFieldDTO {
    pub id: String,
    pub name: Option<String>,
    pub purpose: Option<String>,
    pub required: Option<bool>,
    pub key_map: HashMap<String, String>,
}

#[derive(Clone, Debug)]
pub enum PresentationDefinitionRuleTypeEnum {
    All,
    Pick,
}

#[derive(Clone, Debug)]
pub struct PresentationDefinitionRuleDTO {
    pub r#type: PresentationDefinitionRuleTypeEnum,
    pub min: Option<u32>,
    pub max: Option<u32>,
    pub count: Option<u32>,
}

#[derive(Clone, Debug)]
pub(crate) struct CredentialGroup {
    pub id: String,
    pub name: Option<String>,
    pub purpose: Option<String>,
    pub claims: Vec<CredentialGroupItem>,
    pub applicable_credentials: Vec<Credential>,
    pub inapplicable_credentials: Vec<Credential>,
    pub validity_credential_nbf: Option<OffsetDateTime>,
}

#[derive(Clone, Debug)]
pub(crate) struct CredentialGroupItem {
    pub id: String,
    pub key: String,
    pub required: bool,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct VerificationProtocolCapabilities {
    pub supported_transports: Vec<String>,
    pub did_methods: Vec<DidType>,
}
