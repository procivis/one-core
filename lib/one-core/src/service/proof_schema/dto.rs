use dto_mapper::From;
use shared_types::{ClaimSchemaId, CredentialSchemaId, OrganisationId};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::model::common::{GetListQueryParams, GetListResponse};
use crate::model::proof_schema::{ProofSchema, SortableProofSchemaColumn};
use crate::service::credential_schema::dto::CredentialSchemaListItemResponseDTO;

pub type ProofSchemaId = Uuid;

#[derive(Clone, Debug)]
pub struct ProofClaimSchemaResponseDTO {
    pub id: ClaimSchemaId,
    pub required: bool,
    pub key: String,
    pub data_type: String,
    pub claims: Vec<ProofClaimSchemaResponseDTO>,
}

#[derive(Clone, Debug)]
pub struct GetProofSchemaResponseDTO {
    pub id: ProofSchemaId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub name: String,
    pub organisation_id: OrganisationId,
    pub expire_duration: u32,
    pub proof_input_schemas: Vec<ProofInputSchemaResponseDTO>,
}

#[derive(Clone, Debug)]
pub struct ProofInputSchemaResponseDTO {
    pub claim_schemas: Vec<ProofClaimSchemaResponseDTO>,
    pub credential_schema: CredentialSchemaListItemResponseDTO,
    pub validity_constraint: Option<i64>,
}

#[derive(Clone, Debug, From)]
#[from(ProofSchema)]
pub struct GetProofSchemaListItemDTO {
    pub id: ProofSchemaId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub deleted_at: Option<OffsetDateTime>,
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
    pub proof_input_schemas: Vec<ProofInputSchemaRequestDTO>,
}

#[derive(Clone, Debug)]
pub struct ProofInputSchemaRequestDTO {
    pub credential_schema_id: CredentialSchemaId,
    pub validity_constraint: Option<i64>,
    pub claim_schemas: Vec<CreateProofSchemaClaimRequestDTO>,
}

#[derive(Clone, Debug)]
pub struct ProofSchemaShareResponseDTO {
    pub url: String,
}
