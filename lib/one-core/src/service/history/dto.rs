use one_dto_mapper::{From, convert_inner};
use serde::{Deserialize, Serialize};
use shared_types::{
    CredentialId, CredentialSchemaId, EntityId, HistoryId, IdentifierId, OrganisationId, ProofId,
    ProofSchemaId, TrustCollectionId,
};
use time::OffsetDateTime;

use crate::error::ErrorCode;
use crate::model::common::GetListResponse;
use crate::model::history::{
    History, HistoryAction, HistoryEntityType, HistoryErrorMetadata, HistoryMetadata,
    HistorySearchEnum, HistorySource, TrustResolutionMetadata, TrustResolutionResult,
    WalletRelyingPartyMetadata,
};
use crate::service::backup::dto::UnexportableEntitiesResponseDTO;

#[derive(Debug, Clone, Serialize, Deserialize, From)]
#[from(HistoryMetadata)]
pub enum HistoryMetadataResponse {
    UnexportableEntities(UnexportableEntitiesResponseDTO),
    ErrorMetadata(HistoryErrorMetadataDTO),
    WalletUnitJWT(String),
    External(serde_json::Value),
    WalletRelyingParty(WalletRelyingPartyMetadataDTO),
    TrustResolution(TrustResolutionMetadataDTO),
}

#[derive(Debug, Clone, Serialize, Deserialize, From)]
#[from(HistoryErrorMetadata)]
pub struct HistoryErrorMetadataDTO {
    pub error_code: ErrorCode,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, From)]
#[from(WalletRelyingPartyMetadata)]
pub struct WalletRelyingPartyMetadataDTO {
    pub name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, From)]
#[from(TrustResolutionMetadata)]
pub struct TrustResolutionMetadataDTO {
    pub result: TrustResolutionResult,
}

#[derive(Debug, Clone, Serialize, Deserialize, From)]
#[from(History)]
pub struct HistoryResponseDTO {
    pub created_date: OffsetDateTime,
    pub id: HistoryId,
    pub action: HistoryAction,
    pub name: String,
    pub entity_id: Option<EntityId>,
    pub entity_type: HistoryEntityType,
    pub organisation_id: Option<OrganisationId>,
    #[from(with_fn = convert_inner)]
    pub metadata: Option<HistoryMetadataResponse>,
    pub source: HistorySource,
    pub target: Option<String>,
    pub user: Option<String>,
}

pub type GetHistoryListResponseDTO = GetListResponse<HistoryResponseDTO>;

#[derive(Clone, Debug, Default)]
pub struct HistoryFilterParamsDTO {
    pub organisation_ids: Option<Vec<OrganisationId>>,
    pub entity_ids: Option<Vec<EntityId>>,
    pub entity_types: Option<Vec<HistoryEntityType>>,
    pub actions: Option<Vec<HistoryAction>>,
    pub identifier_id: Option<IdentifierId>,
    pub created_date_after: Option<OffsetDateTime>,
    pub created_date_before: Option<OffsetDateTime>,
    pub credential_id: Option<CredentialId>,
    pub credential_schema_id: Option<CredentialSchemaId>,
    pub proof_id: Option<ProofId>,
    pub proof_schema_id: Option<ProofSchemaId>,
    pub trust_collection_id: Option<TrustCollectionId>,
    pub users: Option<Vec<String>>,
    pub sources: Option<Vec<HistorySource>>,
    pub search_query: Option<String>,
    pub search_type: Option<HistorySearchEnum>,
}

#[derive(Debug, Clone)]
pub struct CreateHistoryRequestDTO {
    pub action: HistoryAction,
    pub name: String,
    pub entity_id: Option<EntityId>,
    pub entity_type: HistoryEntityType,
    pub organisation_id: Option<OrganisationId>,
    pub metadata: Option<serde_json::Value>,
    pub source: HistorySource,
    pub target: Option<String>,
}
