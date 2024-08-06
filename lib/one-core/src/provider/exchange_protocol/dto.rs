use std::collections::HashMap;

use dto_mapper::{convert_inner, From, Into};
use one_providers::common_models::credential_schema::WalletStorageTypeEnum;
use serde::{Deserialize, Serialize};
use shared_types::DidValue;
use time::OffsetDateTime;

use crate::model::credential::Credential;
use crate::model::credential_schema::CredentialSchemaType;
use crate::service::credential::dto::CredentialDetailResponseDTO;

#[derive(Clone)]
pub enum InvitationResponse {
    Credential(Box<CredentialDetailResponseDTO>),
    Proof {
        proof_request: ConnectVerifierResponse,
        proof_id: String,
    },
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// deserializes matching `ConnectVerifierResponseRestDTO`
pub struct ConnectVerifierResponse {
    pub claims: Vec<ProofClaimSchema>,
    pub verifier_did: DidValue,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
/// deserializes matching `ProofRequestClaimRestDTO`
pub struct ProofClaimSchema {
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
pub struct ProofCredentialSchema {
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

#[derive(Clone, Debug, From, Into)]
#[from(one_providers::exchange_protocol::openid4vc::model::PresentationDefinitionResponseDTO)]
#[into(one_providers::exchange_protocol::openid4vc::model::PresentationDefinitionResponseDTO)]
pub struct PresentationDefinitionResponseDTO {
    #[from(with_fn = convert_inner)]
    #[into(with_fn = convert_inner)]
    pub request_groups: Vec<PresentationDefinitionRequestGroupResponseDTO>,
    #[from(with_fn = convert_inner)]
    #[into(with_fn = convert_inner)]
    pub credentials: Vec<CredentialDetailResponseDTO>,
}

#[derive(Clone, Debug, From, Into)]
#[from(one_providers::exchange_protocol::openid4vc::model::PresentationDefinitionRequestGroupResponseDTO)]
#[into(one_providers::exchange_protocol::openid4vc::model::PresentationDefinitionRequestGroupResponseDTO)]
pub struct PresentationDefinitionRequestGroupResponseDTO {
    pub id: String,
    pub name: Option<String>,
    pub purpose: Option<String>,
    pub rule: PresentationDefinitionRuleDTO,
    #[from(with_fn = convert_inner)]
    #[into(with_fn = convert_inner)]
    pub requested_credentials: Vec<PresentationDefinitionRequestedCredentialResponseDTO>,
}

#[derive(Clone, Debug, From, Into)]
#[from(one_providers::exchange_protocol::openid4vc::model::PresentationDefinitionRequestedCredentialResponseDTO)]
#[into(one_providers::exchange_protocol::openid4vc::model::PresentationDefinitionRequestedCredentialResponseDTO)]
pub struct PresentationDefinitionRequestedCredentialResponseDTO {
    pub id: String,
    pub name: Option<String>,
    pub purpose: Option<String>,
    #[from(with_fn = convert_inner)]
    #[into(with_fn = convert_inner)]
    pub fields: Vec<PresentationDefinitionFieldDTO>,
    #[from(with_fn = convert_inner)]
    #[into(with_fn = convert_inner)]
    pub applicable_credentials: Vec<String>,
    pub validity_credential_nbf: Option<OffsetDateTime>,
}

#[derive(Clone, Debug, From, Into)]
#[from(one_providers::exchange_protocol::openid4vc::model::PresentationDefinitionFieldDTO)]
#[into(one_providers::exchange_protocol::openid4vc::model::PresentationDefinitionFieldDTO)]
pub struct PresentationDefinitionFieldDTO {
    pub id: String,
    pub name: Option<String>,
    pub purpose: Option<String>,
    pub required: Option<bool>,
    pub key_map: HashMap<String, String>,
}

#[derive(Clone, Debug, From, Into)]
#[from(one_providers::exchange_protocol::openid4vc::model::PresentationDefinitionRuleTypeEnum)]
#[into(one_providers::exchange_protocol::openid4vc::model::PresentationDefinitionRuleTypeEnum)]
pub enum PresentationDefinitionRuleTypeEnum {
    All,
    Pick,
}

#[derive(Clone, Debug, From, Into)]
#[from(one_providers::exchange_protocol::openid4vc::model::PresentationDefinitionRuleDTO)]
#[into(one_providers::exchange_protocol::openid4vc::model::PresentationDefinitionRuleDTO)]
pub struct PresentationDefinitionRuleDTO {
    pub r#type: PresentationDefinitionRuleTypeEnum,
    pub min: Option<u32>,
    pub max: Option<u32>,
    pub count: Option<u32>,
}

#[derive(Clone, Debug, Into, From)]
#[into(one_providers::exchange_protocol::openid4vc::model::CredentialGroup)]
#[from(one_providers::exchange_protocol::openid4vc::model::CredentialGroup)]
pub struct CredentialGroup {
    pub id: String,
    pub name: Option<String>,
    pub purpose: Option<String>,
    #[into(with_fn = convert_inner)]
    #[from(with_fn = convert_inner)]
    pub claims: Vec<CredentialGroupItem>,
    #[into(with_fn = convert_inner)]
    #[from(with_fn = convert_inner)]
    pub applicable_credentials: Vec<Credential>,
    pub validity_credential_nbf: Option<OffsetDateTime>,
}

#[derive(Clone, Debug, Into, From)]
#[into(one_providers::exchange_protocol::openid4vc::model::CredentialGroupItem)]
#[from(one_providers::exchange_protocol::openid4vc::model::CredentialGroupItem)]
pub struct CredentialGroupItem {
    pub id: String,
    pub key: String,
    pub required: bool,
}
