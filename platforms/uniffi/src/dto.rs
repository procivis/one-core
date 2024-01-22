use crate::error::NativeKeyStorageError;
use crate::mapper::serialize_config_entity;
use crate::utils::TimestampFormat;
use dto_mapper::{From, TryInto};
use one_core::service::credential::dto::CredentialRole;
use one_core::service::error::ServiceError;
use one_core::service::ssi_holder::dto::PresentationSubmitCredentialRequestDTO;
use one_core::{
    common_mapper::convert_inner,
    model::did::DidType,
    provider::{
        key_storage::GeneratedKey,
        transport_protocol::dto::{
            PresentationDefinitionFieldDTO, PresentationDefinitionRequestGroupResponseDTO,
            PresentationDefinitionRequestedCredentialResponseDTO,
            PresentationDefinitionResponseDTO, PresentationDefinitionRuleDTO,
            PresentationDefinitionRuleTypeEnum,
        },
    },
    service::{
        config::dto::ConfigDTO,
        credential::dto::{
            CredentialRevocationCheckResponseDTO, CredentialStateEnum, GetCredentialListResponseDTO,
        },
        credential_schema::dto::CredentialSchemaListItemResponseDTO,
    },
};
use std::collections::HashMap;
use std::str::FromStr;

#[derive(From)]
#[convert(from = "ConfigDTO")]
pub struct ConfigBindingDTO {
    #[convert(with_fn = serialize_config_entity)]
    pub format: HashMap<String, String>,
    #[convert(with_fn = serialize_config_entity)]
    pub exchange: HashMap<String, String>,
    #[convert(with_fn = serialize_config_entity)]
    pub transport: HashMap<String, String>,
    #[convert(with_fn = serialize_config_entity)]
    pub revocation: HashMap<String, String>,
    #[convert(with_fn = serialize_config_entity)]
    pub did: HashMap<String, String>,
    #[convert(with_fn = serialize_config_entity)]
    pub datatype: HashMap<String, String>,
    #[convert(with_fn = serialize_config_entity)]
    pub key_algorithm: HashMap<String, String>,
    #[convert(with_fn = serialize_config_entity)]
    pub key_storage: HashMap<String, String>,
}

#[derive(From)]
#[convert(from = "CredentialStateEnum")]
pub enum CredentialStateBindingEnum {
    Created,
    Pending,
    Offered,
    Accepted,
    Rejected,
    Revoked,
    Error,
}

pub type VersionBindingDTO = one_core::Version;

#[derive(From, Clone)]
#[convert(from = CredentialRole, into = CredentialRole)]
pub enum CredentialRoleBindingDTO {
    Holder,
    Issuer,
    Verifier,
}

pub struct ListQueryBindingDTO {
    pub page: u32,
    pub page_size: u32,
    pub organisation_id: String,
    pub role: Option<CredentialRoleBindingDTO>,
}

#[derive(From)]
#[convert(from = "GetCredentialListResponseDTO")]
pub struct CredentialListBindingDTO {
    #[convert(with_fn = convert_inner)]
    pub values: Vec<CredentialListItemBindingDTO>,
    pub total_pages: u64,
    pub total_items: u64,
}

pub struct CredentialDetailBindingDTO {
    pub id: String,
    pub created_date: String,
    pub issuance_date: String,
    pub last_modified: String,
    pub revocation_date: Option<String>,
    pub issuer_did: Option<String>,
    pub state: CredentialStateBindingEnum,
    pub schema: CredentialSchemaBindingDTO,
    pub claims: Vec<ClaimBindingDTO>,
    pub redirect_uri: Option<String>,
    pub role: CredentialRoleBindingDTO,
}

pub struct CredentialListItemBindingDTO {
    pub id: String,
    pub created_date: String,
    pub issuance_date: String,
    pub last_modified: String,
    pub revocation_date: Option<String>,
    pub issuer_did: Option<String>,
    pub state: CredentialStateBindingEnum,
    pub schema: CredentialSchemaBindingDTO,
    pub role: CredentialRoleBindingDTO,
}

#[derive(From)]
#[convert(from = CredentialSchemaListItemResponseDTO)]
pub struct CredentialSchemaBindingDTO {
    #[convert(with_fn_ref = "ToString::to_string")]
    pub id: String,
    #[convert(with_fn_ref = "TimestampFormat::format_timestamp")]
    pub created_date: String,
    #[convert(with_fn_ref = "TimestampFormat::format_timestamp")]
    pub last_modified: String,
    pub name: String,
    pub format: String,
    pub revocation_method: String,
}

pub struct ClaimBindingDTO {
    pub id: String,
    pub key: String,
    pub data_type: String,
    pub value: String,
}

pub enum HandleInvitationResponseBindingEnum {
    CredentialIssuance {
        interaction_id: String,
        credential_ids: Vec<String>,
    },
    ProofRequest {
        interaction_id: String,
        proof_id: String,
    },
}

pub struct ProofRequestBindingDTO {
    pub id: String,
    pub created_date: String,
    pub last_modified: String,
    pub claims: Vec<ProofRequestClaimBindingDTO>,
    pub verifier_did: Option<String>,
    pub transport: String,
    pub redirect_uri: Option<String>,
    pub credentials: Vec<CredentialDetailBindingDTO>,
}

pub struct ProofRequestClaimBindingDTO {
    pub id: String,
    pub key: String,
    pub data_type: String,
    pub required: bool,
    pub credential_schema: CredentialSchemaBindingDTO,
}

#[derive(TryInto)]
#[try_into(T = PresentationSubmitCredentialRequestDTO, Error = ServiceError)]
pub struct PresentationSubmitCredentialRequestBindingDTO {
    #[try_into(with_fn_ref = "uuid::Uuid::from_str")]
    pub credential_id: String,
    #[try_into(infallible)]
    pub submit_claims: Vec<String>,
}

#[derive(From)]
#[convert(from = "PresentationDefinitionResponseDTO")]
pub struct PresentationDefinitionBindingDTO {
    #[convert(with_fn = convert_inner)]
    pub request_groups: Vec<PresentationDefinitionRequestGroupBindingDTO>,
}

#[derive(From)]
#[convert(from = "PresentationDefinitionRequestGroupResponseDTO")]
pub struct PresentationDefinitionRequestGroupBindingDTO {
    pub id: String,
    pub name: Option<String>,
    pub purpose: Option<String>,
    pub rule: PresentationDefinitionRuleBindingDTO,
    #[convert(with_fn = convert_inner)]
    pub requested_credentials: Vec<PresentationDefinitionRequestedCredentialBindingDTO>,
}

#[derive(From)]
#[convert(from = "PresentationDefinitionRequestedCredentialResponseDTO")]
pub struct PresentationDefinitionRequestedCredentialBindingDTO {
    pub id: String,
    pub name: Option<String>,
    pub purpose: Option<String>,
    #[convert(with_fn = convert_inner)]
    pub fields: Vec<PresentationDefinitionFieldBindingDTO>,
    #[convert(with_fn = convert_inner)]
    pub applicable_credentials: Vec<String>,
}

#[derive(From)]
#[convert(from = PresentationDefinitionFieldDTO)]
pub struct PresentationDefinitionFieldBindingDTO {
    pub id: String,
    pub name: Option<String>,
    pub purpose: Option<String>,
    #[convert(unwrap_or = true)]
    pub required: bool,
    pub key_map: HashMap<String, String>,
}

#[derive(From)]
#[convert(from = "PresentationDefinitionRuleTypeEnum")]
pub enum PresentationDefinitionRuleTypeBindingEnum {
    All,
    Pick,
}

#[derive(From)]
#[convert(from = "PresentationDefinitionRuleDTO")]
pub struct PresentationDefinitionRuleBindingDTO {
    pub r#type: PresentationDefinitionRuleTypeBindingEnum,
    pub min: Option<u32>,
    pub max: Option<u32>,
    pub count: Option<u32>,
}

pub struct KeyRequestBindingDTO {
    pub organisation_id: String,
    pub key_type: String,
    pub key_params: HashMap<String, String>,
    pub name: String,
    pub storage_type: String,
    pub storage_params: HashMap<String, String>,
}

#[derive(From)]
#[convert(into = "DidType")]
pub enum DidTypeBindingEnum {
    Local,
    Remote,
}

pub struct DidRequestBindingDTO {
    pub organisation_id: String,
    pub name: String,
    pub did_method: String,
    pub did_type: DidTypeBindingEnum,
    pub keys: DidRequestKeysBindingDTO,
    pub params: HashMap<String, String>,
}

pub struct DidRequestKeysBindingDTO {
    pub authentication: Vec<String>,
    pub assertion: Vec<String>,
    pub key_agreement: Vec<String>,
    pub capability_invocation: Vec<String>,
    pub capability_delegation: Vec<String>,
}

#[derive(From)]
#[convert(from = "CredentialRevocationCheckResponseDTO")]
pub struct CredentialRevocationCheckResponseBindingDTO {
    #[convert(with_fn_ref = "uuid::Uuid::to_string")]
    pub credential_id: String,
    pub status: CredentialStateBindingEnum,
    pub success: bool,
    pub reason: Option<String>,
}

#[derive(From)]
#[convert(into = "GeneratedKey")]
pub struct GeneratedKeyBindingDTO {
    pub key_reference: Vec<u8>,
    pub public_key: Vec<u8>,
}

pub trait NativeKeyStorage: Send + Sync {
    fn generate_key(
        &self,
        key_alias: String,
    ) -> Result<GeneratedKeyBindingDTO, NativeKeyStorageError>;
    fn sign(
        &self,
        key_reference: Vec<u8>,
        message: Vec<u8>,
    ) -> Result<Vec<u8>, NativeKeyStorageError>;
}
