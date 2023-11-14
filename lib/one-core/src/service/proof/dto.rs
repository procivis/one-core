use shared_types::{DidId, DidValue};
use std::collections::HashMap;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    model::{
        common::{GetListQueryParams, GetListResponse},
        organisation::OrganisationId,
        proof::{ProofStateEnum, SortableProofColumn},
    },
    service::{
        credential::dto::CredentialDetailResponseDTO,
        proof_schema::dto::{
            GetProofSchemaListItemDTO, ProofClaimSchemaResponseDTO, ProofSchemaId,
        },
    },
};

pub type ProofId = Uuid;

#[derive(Clone, Debug)]
pub struct CreateProofRequestDTO {
    pub proof_schema_id: ProofSchemaId,
    pub verifier_did_id: DidId,
    pub transport: String,
}

#[derive(Clone, Debug)]
pub struct CreateProofResponseDTO {
    pub id: ProofId,
}

#[derive(Clone, Debug)]
pub struct ProofDetailResponseDTO {
    pub id: ProofId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub issuance_date: OffsetDateTime,
    pub requested_date: Option<OffsetDateTime>,
    pub completed_date: Option<OffsetDateTime>,
    pub verifier_did: DidValue,
    pub holder_did_id: Option<DidId>,
    pub transport: String,
    pub state: ProofStateEnum,
    pub organisation_id: OrganisationId,
    pub schema: Option<GetProofSchemaListItemDTO>,
    pub claims: Vec<ProofClaimDTO>,
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
pub struct ProofListItemResponseDTO {
    pub id: ProofId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub issuance_date: OffsetDateTime,
    pub requested_date: Option<OffsetDateTime>,
    pub completed_date: Option<OffsetDateTime>,
    pub verifier_did: DidValue,
    pub transport: String,
    pub state: ProofStateEnum,
    pub schema: Option<GetProofSchemaListItemDTO>,
}

#[derive(Clone, Debug)]
pub struct ProofClaimDTO {
    pub schema: ProofClaimSchemaResponseDTO,
    pub value: Option<String>,
}

pub type GetProofListResponseDTO = GetListResponse<ProofListItemResponseDTO>;
pub type GetProofQueryDTO = GetListQueryParams<SortableProofColumn>;
