use crate::{
    model::history::{GetHistoryList, History},
    service::{
        error::ServiceError,
        history::dto::{GetHistoryListResponseDTO, HistoryResponseDTO},
    },
};
use dto_mapper::iterable_try_into;

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
            organisation_id: organisation.id.into(),
        })
    }
}

impl TryFrom<GetHistoryList> for GetHistoryListResponseDTO {
    type Error = ServiceError;

    fn try_from(value: GetHistoryList) -> Result<Self, Self::Error> {
        Ok(Self {
            values: iterable_try_into(value.values)?,
            total_pages: value.total_pages,
            total_items: value.total_items,
        })
    }
}
