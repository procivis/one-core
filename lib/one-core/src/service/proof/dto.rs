use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    model::{
        common::{GetListQueryParams, GetListResponse},
        proof::{ProofStateEnum, SortableProofColumn},
    },
    service::{
        credential_schema::dto::ClaimSchemaId,
        did::dto::{DidId, DidValue},
        organisation::dto::OrganisationId,
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
    pub claims: Vec<ProofClaimDTO>,
    pub schema: GetProofSchemaListItemDTO,
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
    pub schema: GetProofSchemaListItemDTO,
}

#[derive(Clone, Debug)]
pub struct ProofClaimDTO {
    pub schema: ProofClaimSchemaResponseDTO,
    pub value: Option<String>,
}

pub type GetProofListResponseDTO = GetListResponse<ProofListItemResponseDTO>;
pub type GetProofQueryDTO = GetListQueryParams<SortableProofColumn>;

#[derive(Clone, Debug)]
pub struct ShareProofResponseDTO {
    pub url: String,
}

#[derive(Clone, Debug)]
pub struct CreateProofClaimRequestDTO {
    pub claim_schema_id: ClaimSchemaId,
    pub value: String,
}