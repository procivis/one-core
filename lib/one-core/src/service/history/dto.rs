use one_dto_mapper::{From, convert_inner};
use serde::{Deserialize, Serialize};
use shared_types::{EntityId, HistoryId, OrganisationId};
use time::OffsetDateTime;

use crate::model::common::GetListResponse;
use crate::model::history::{
    History, HistoryAction, HistoryEntityType, HistoryErrorMetadata, HistoryMetadata, HistorySource,
};
use crate::service::backup::dto::UnexportableEntitiesResponseDTO;
use crate::service::error::ErrorCode;

#[derive(Debug, Clone, Serialize, Deserialize, From)]
#[from(HistoryMetadata)]
pub enum HistoryMetadataResponse {
    UnexportableEntities(UnexportableEntitiesResponseDTO),
    ErrorMetadata(HistoryErrorMetadataDTO),
    WalletUnitJWT(String),
    External(serde_json::Value),
}

#[derive(Debug, Clone, Serialize, Deserialize, From)]
#[from(HistoryErrorMetadata)]
pub struct HistoryErrorMetadataDTO {
    pub error_code: ErrorCode,
    pub message: String,
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

#[derive(Debug, Clone)]
pub struct CreateHistoryRequestDTO {
    pub action: HistoryAction,
    pub name: Option<String>,
    pub entity_id: Option<EntityId>,
    pub entity_type: HistoryEntityType,
    pub organisation_id: Option<OrganisationId>,
    pub metadata: Option<serde_json::Value>,
    pub source: HistorySource,
    pub target: Option<String>,
    pub user: Option<String>,
}
