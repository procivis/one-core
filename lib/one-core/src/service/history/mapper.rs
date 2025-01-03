use one_dto_mapper::{convert_inner, try_convert_inner};

use crate::model::history::{GetHistoryList, History};
use crate::service::error::ServiceError;
use crate::service::history::dto::{GetHistoryListResponseDTO, HistoryResponseDTO};

impl TryFrom<History> for HistoryResponseDTO {
    type Error = ServiceError;

    fn try_from(value: History) -> Result<Self, Self::Error> {
        let organisation = value.organisation.ok_or(ServiceError::MappingError(
            "organisation is None".to_string(),
        ))?;

        Ok(Self {
            created_date: value.created_date,
            id: value.id,
            action: value.action,
            entity_id: value.entity_id,
            entity_type: value.entity_type,
            metadata: convert_inner(value.metadata),
            organisation_id: organisation.id,
        })
    }
}

impl TryFrom<GetHistoryList> for GetHistoryListResponseDTO {
    type Error = ServiceError;

    fn try_from(value: GetHistoryList) -> Result<Self, Self::Error> {
        Ok(Self {
            values: try_convert_inner(value.values)?,
            total_pages: value.total_pages,
            total_items: value.total_items,
        })
    }
}
