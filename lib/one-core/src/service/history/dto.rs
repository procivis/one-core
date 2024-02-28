use shared_types::{EntityId, HistoryId, OrganisationId};
use time::OffsetDateTime;

use crate::model::{
    common::GetListResponse,
    history::{HistoryAction, HistoryEntityType},
};

pub struct HistoryResponseDTO {
    pub created_date: OffsetDateTime,
    pub id: HistoryId,
    pub action: HistoryAction,
    pub entity_id: Option<EntityId>,
    pub entity_type: HistoryEntityType,
    pub organisation_id: OrganisationId,
}

pub type GetHistoryListResponseDTO = GetListResponse<HistoryResponseDTO>;
