use one_dto_mapper::From;
use serde::{Deserialize, Serialize};
use shared_types::{EntityId, HistoryId, OrganisationId};
use time::OffsetDateTime;

use crate::model::common::GetListResponse;
use crate::model::history::{HistoryAction, HistoryEntityType, HistoryMetadata};
use crate::service::backup::dto::UnexportableEntitiesResponseDTO;

#[derive(Debug, Clone, Serialize, Deserialize, From)]
#[from(HistoryMetadata)]
pub enum HistoryMetadataResponse {
    UnexportableEntities(UnexportableEntitiesResponseDTO),
}

pub struct HistoryResponseDTO {
    pub created_date: OffsetDateTime,
    pub id: HistoryId,
    pub action: HistoryAction,
    pub entity_id: Option<EntityId>,
    pub entity_type: HistoryEntityType,
    pub organisation_id: OrganisationId,
    pub metadata: Option<HistoryMetadataResponse>,
}

pub type GetHistoryListResponseDTO = GetListResponse<HistoryResponseDTO>;
