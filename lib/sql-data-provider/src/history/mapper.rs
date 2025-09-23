use one_core::model::history::{GetHistoryList, History};
use one_core::repository::error::DataLayerError;
use one_dto_mapper::try_convert_inner;
use sea_orm::ActiveValue::Set;

use crate::common::calculate_pages_count;
use crate::entity::history;

impl TryFrom<history::Model> for History {
    type Error = DataLayerError;

    fn try_from(value: history::Model) -> Result<Self, Self::Error> {
        let metadata = value
            .metadata
            .as_deref()
            .map(serde_json::from_str)
            .transpose()
            .map_err(|_| Self::Error::MappingError)?;

        Ok(Self {
            id: value.id,
            created_date: value.created_date,
            action: value.action.into(),
            entity_id: value.entity_id,
            entity_type: value.entity_type.into(),
            metadata,
            organisation_id: value.organisation_id,
            name: value.name,
            target: value.target,
            user: value.user,
        })
    }
}

impl TryFrom<History> for history::ActiveModel {
    type Error = DataLayerError;

    fn try_from(value: History) -> Result<Self, Self::Error> {
        let metadata = value
            .metadata
            .as_ref()
            .map(serde_json::to_string)
            .transpose()
            .map_err(|_| Self::Error::MappingError)?;

        Ok(Self {
            id: Set(value.id),
            created_date: Set(value.created_date),
            action: Set(value.action.into()),
            entity_id: Set(value.entity_id),
            entity_type: Set(value.entity_type.into()),
            metadata: Set(metadata),
            organisation_id: Set(value.organisation_id),
            name: Set(value.name),
            target: Set(value.target),
            user: Set(value.user),
        })
    }
}

pub(super) fn create_list_response(
    history_list: Vec<history::Model>,
    limit: Option<u64>,
    items_count: u64,
) -> Result<GetHistoryList, DataLayerError> {
    Ok(GetHistoryList {
        values: try_convert_inner(history_list)?,
        total_pages: calculate_pages_count(items_count, limit.unwrap_or(0)),
        total_items: items_count,
    })
}
