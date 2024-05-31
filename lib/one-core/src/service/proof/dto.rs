use shared_types::{DidId, KeyId, OrganisationId};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::model::common::{GetListQueryParams, GetListResponse};
use crate::model::proof::{ProofStateEnum, SortableProofColumn};
use crate::service::credential::dto::CredentialDetailResponseDTO;
use crate::service::credential_schema::dto::CredentialSchemaListItemResponseDTO;
use crate::service::did::dto::DidListItemResponseDTO;
use crate::service::proof_schema::dto::{
    GetProofSchemaListItemDTO, ProofClaimSchemaResponseDTO, ProofSchemaId,
};

pub type ProofId = Uuid;

#[derive(Clone, Debug)]
pub struct CreateProofRequestDTO {
    pub proof_schema_id: ProofSchemaId,
    pub verifier_did_id: DidId,
    pub exchange: String,
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
    pub exchange: String,
    pub state: ProofStateEnum,
    pub organisation_id: Option<OrganisationId>,
    pub schema: Option<GetProofSchemaListItemDTO>,
    pub redirect_uri: Option<String>,
    pub proof_inputs: Vec<ProofInputDTO>,
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
    pub exchange: String,
    pub state: ProofStateEnum,
    pub schema: Option<GetProofSchemaListItemDTO>,
}

#[derive(Clone, Debug)]
pub struct ProofClaimDTO {
    pub schema: ProofClaimSchemaResponseDTO,
    pub value: Option<ProofClaimValueDTO>,
}

#[derive(Clone, Debug)]
pub enum ProofClaimValueDTO {
    Value(String),
    Claims(Vec<ProofClaimDTO>),
}

#[derive(Clone, Debug)]
pub struct ProofInputDTO {
    pub claims: Vec<ProofClaimDTO>,
    pub credential: Option<CredentialDetailResponseDTO>,
    pub credential_schema: CredentialSchemaListItemResponseDTO,
    pub validity_constraint: Option<i64>,
}

pub type GetProofListResponseDTO = GetListResponse<ProofListItemResponseDTO>;
pub type GetProofQueryDTO = GetListQueryParams<SortableProofColumn>;
