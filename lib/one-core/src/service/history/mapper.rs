use one_dto_mapper::convert_inner;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::model::history::{GetHistoryList, History, HistoryMetadata};
use crate::service::history::dto::{CreateHistoryRequestDTO, GetHistoryListResponseDTO};

impl From<GetHistoryList> for GetHistoryListResponseDTO {
    fn from(value: GetHistoryList) -> Self {
        Self {
            values: convert_inner(value.values),
            total_pages: value.total_pages,
            total_items: value.total_items,
        }
    }
}

impl From<CreateHistoryRequestDTO> for History {
    fn from(value: CreateHistoryRequestDTO) -> Self {
        Self {
            id: Uuid::new_v4().into(),
            created_date: OffsetDateTime::now_utc(),
            action: value.action,
            name: value.name.unwrap_or_default(),
            target: value.target,
            source: value.source,
            entity_id: value.entity_id,
            entity_type: value.entity_type,
            metadata: value.metadata.map(HistoryMetadata::External),
            organisation_id: value.organisation_id,
            user: None,
        }
    }
}
