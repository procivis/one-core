use dto_mapper::convert_inner;
use sea_orm::ActiveValue::Set;
use time::OffsetDateTime;

use one_core::{
    model::{
        history::{GetHistoryList, History},
        organisation::Organisation,
    },
    repository::error::DataLayerError,
};

use crate::{common::calculate_pages_count, entity::history};

impl From<history::Model> for History {
    fn from(value: history::Model) -> Self {
        Self {
            id: value.id,
            created_date: value.created_date,
            action: value.action.into(),
            entity_id: value.entity_id,
            entity_type: value.entity_type.into(),
            organisation: Some(Organisation {
                id: value.organisation_id.into(),
                created_date: OffsetDateTime::UNIX_EPOCH,
                last_modified: OffsetDateTime::UNIX_EPOCH,
            }),
        }
    }
}

impl TryFrom<History> for history::ActiveModel {
    type Error = DataLayerError;

    fn try_from(value: History) -> Result<Self, Self::Error> {
        let organisation = value.organisation.ok_or(DataLayerError::MappingError)?;

        Ok(Self {
            id: Set(value.id),
            created_date: Set(value.created_date),
            action: Set(value.action.into()),
            entity_id: Set(value.entity_id),
            entity_type: Set(value.entity_type.into()),
            organisation_id: Set(organisation.id.into()),
        })
    }
}

pub(crate) fn create_list_response(
    history_list: Vec<history::Model>,
    limit: Option<u64>,
    items_count: u64,
) -> GetHistoryList {
    GetHistoryList {
        values: convert_inner(history_list),
        total_pages: calculate_pages_count(items_count, limit.unwrap_or(0)),
        total_items: items_count,
    }
}
