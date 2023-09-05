use std::str::FromStr;

use one_core::{model::organisation::Organisation, repository::error::DataLayerError};
use sea_orm::Set;
use uuid::Uuid;

use crate::entity::organisation;

impl From<Organisation> for organisation::ActiveModel {
    fn from(value: Organisation) -> Self {
        Self {
            id: Set(value.id.to_string()),
            created_date: Set(value.created_date),
            last_modified: Set(value.last_modified),
        }
    }
}

impl TryFrom<organisation::Model> for Organisation {
    type Error = DataLayerError;

    fn try_from(value: organisation::Model) -> Result<Self, Self::Error> {
        let id = Uuid::from_str(&value.id).map_err(|_| DataLayerError::MappingError)?;
        Ok(Self {
            id,
            created_date: value.created_date,
            last_modified: value.last_modified,
        })
    }
}
