use std::str::FromStr;

use one_core::{
    model::{did::Did, organisation::Organisation},
    repository::error::DataLayerError,
};
use sea_orm::Set;
use uuid::Uuid;

use crate::entity::organisation;

pub(crate) fn organisation_from_models(
    organisation: organisation::Model,
    did_list: Option<Vec<Did>>,
) -> Result<Organisation, DataLayerError> {
    Uuid::from_str(&organisation.id)
        .ok()
        .map(|id| Organisation {
            id,
            created_date: organisation.created_date,
            last_modified: organisation.last_modified,
            did: did_list,
        })
        .ok_or(DataLayerError::MappingError)
}

impl From<Organisation> for organisation::ActiveModel {
    fn from(value: Organisation) -> Self {
        Self {
            id: Set(value.id.to_string()),
            created_date: Set(value.created_date),
            last_modified: Set(value.last_modified),
        }
    }
}
