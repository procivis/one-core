use crate::service::credential::dto::CredentialDetailResponseDTO;
use crate::{
    model::{
        common::{GetListQueryParams, GetListResponse},
        proof::{ProofStateEnum, SortableProofColumn},
    },
    service::{
        did::dto::DidListItemResponseDTO,
        proof_schema::dto::{
            GetProofSchemaListItemDTO, ProofClaimSchemaResponseDTO, ProofSchemaId,
        },
    },
};
use shared_types::{DidId, KeyId, OrganisationId};
use time::OffsetDateTime;
use uuid::Uuid;

pub type ProofId = Uuid;

#[derive(Clone, Debug)]
pub struct CreateProofRequestDTO {
    pub proof_schema_id: ProofSchemaId,
    pub verifier_did_id: DidId,
    pub transport: String,
    pub redirect_uri: Option<String>,
    pub verifier_key: Option<KeyId>,
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
    pub verifier_did: Option<DidListItemResponseDTO>,
    pub holder_did_id: Option<DidId>,
    pub transport: String,
    pub state: ProofStateEnum,
    pub organisation_id: OrganisationId,
    pub schema: Option<GetProofSchemaListItemDTO>,
    pub claims: Vec<ProofClaimDTO>,
    pub redirect_uri: Option<String>,
    pub credentials: Vec<CredentialDetailResponseDTO>,
}

#[derive(Clone, Debug)]
pub struct ProofListItemResponseDTO {
    pub id: ProofId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub issuance_date: OffsetDateTime,
    pub requested_date: Option<OffsetDateTime>,
    pub completed_date: Option<OffsetDateTime>,
    pub verifier_did: Option<DidListItemResponseDTO>,
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
