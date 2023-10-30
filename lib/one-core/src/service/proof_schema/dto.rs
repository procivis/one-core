use dto_mapper::From;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    model::{
        claim_schema::ClaimSchemaId,
        common::{GetListQueryParams, GetListResponse},
        organisation::OrganisationId,
        proof_schema::{ProofSchema, SortableProofSchemaColumn},
    },
    service::credential_schema::dto::CredentialSchemaListItemResponseDTO,
};

pub type ProofSchemaId = Uuid;

#[derive(Clone, Debug)]
pub struct ProofClaimSchemaResponseDTO {
    pub id: ClaimSchemaId,
    pub required: bool,
    pub key: String,
    pub data_type: String,
    pub credential_schema: CredentialSchemaListItemResponseDTO,
}

#[derive(Clone, Debug)]
pub struct GetProofSchemaResponseDTO {
    pub id: ProofSchemaId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub name: String,
    pub organisation_id: OrganisationId,
    pub expire_duration: u32,
    pub claim_schemas: Vec<ProofClaimSchemaResponseDTO>,
}

#[derive(Clone, Debug, From)]
#[convert(from = "ProofSchema")]
pub struct GetProofSchemaListItemDTO {
    pub id: ProofSchemaId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub name: String,
    pub expire_duration: u32,
}

pub type GetProofSchemaListResponseDTO = GetListResponse<GetProofSchemaListItemDTO>;
pub type GetProofSchemaQueryDTO = GetListQueryParams<SortableProofSchemaColumn>;

#[derive(Clone, Debug)]
pub struct CreateProofSchemaClaimRequestDTO {
    pub id: ClaimSchemaId,
    pub required: bool,
}

#[derive(Clone, Debug)]
pub struct CreateProofSchemaRequestDTO {
    pub name: String,
    pub organisation_id: OrganisationId,
    pub expire_duration: u32,
    pub claim_schemas: Vec<CreateProofSchemaClaimRequestDTO>,
}
