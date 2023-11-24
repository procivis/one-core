use crate::error::NativeKeyStorageError;
use dto_mapper::From;
use one_core::{
    common_mapper::vector_into,
    model::did::DidType,
    provider::{
        key_storage::GeneratedKey,
        transport_protocol::dto::{
            PresentationDefinitionRequestGroupResponseDTO,
            PresentationDefinitionRequestedCredentialResponseDTO,
            PresentationDefinitionResponseDTO, PresentationDefinitionRuleDTO,
            PresentationDefinitionRuleTypeEnum,
        },
    },
    service::credential::dto::{
        CredentialRevocationCheckResponseDTO, CredentialStateEnum, GetCredentialListResponseDTO,
    },
};
use std::collections::HashMap;

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

pub struct ListQueryBindingDTO {
    pub page: u32,
    pub page_size: u32,
    pub organisation_id: String,
}

#[derive(From)]
#[convert(from = "GetCredentialListResponseDTO")]
pub struct CredentialListBindingDTO {
    #[convert(with_fn = "vector_into")]
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
    pub claims: Vec<ClaimBindingDTO>,
    pub schema: CredentialSchemaBindingDTO,
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
}

pub struct CredentialSchemaBindingDTO {
    pub id: String,
    pub created_date: String,
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
}

pub struct ProofRequestClaimBindingDTO {
    pub id: String,
    pub key: String,
    pub data_type: String,
    pub required: bool,
    pub credential_schema: CredentialSchemaBindingDTO,
}

pub struct PresentationSubmitCredentialRequestBindingDTO {
    pub credential_id: String,
    pub submit_claims: Vec<String>,
}

#[derive(From)]
#[convert(from = "PresentationDefinitionResponseDTO")]
pub struct PresentationDefinitionBindingDTO {
    #[convert(with_fn = "vector_into")]
    pub request_groups: Vec<PresentationDefinitionRequestGroupBindingDTO>,
}

#[derive(From)]
#[convert(from = "PresentationDefinitionRequestGroupResponseDTO")]
pub struct PresentationDefinitionRequestGroupBindingDTO {
    pub id: String,
    pub name: Option<String>,
    pub purpose: Option<String>,
    pub rule: PresentationDefinitionRuleBindingDTO,
    #[convert(with_fn = "vector_into")]
    pub requested_credentials: Vec<PresentationDefinitionRequestedCredentialBindingDTO>,
}

#[derive(From)]
#[convert(from = "PresentationDefinitionRequestedCredentialResponseDTO")]
pub struct PresentationDefinitionRequestedCredentialBindingDTO {
    pub id: String,
    pub name: Option<String>,
    pub purpose: Option<String>,
    #[convert(with_fn = "vector_into")]
    pub fields: Vec<PresentationDefinitionFieldBindingDTO>,
    #[convert(with_fn = "vector_into")]
    pub applicable_credentials: Vec<String>,
}

pub struct PresentationDefinitionFieldBindingDTO {
    pub id: String,
    pub name: Option<String>,
    pub purpose: Option<String>,
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
