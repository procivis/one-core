use std::str::FromStr;

use one_core::{model::interaction::Interaction, repository::error::DataLayerError};
use sea_orm::Set;
use uuid::Uuid;

use crate::entity::interaction;

impl From<Interaction> for interaction::ActiveModel {
    fn from(value: Interaction) -> Self {
        Self {
            id: Set(value.id.to_string()),
            created_date: Set(value.created_date),
            last_modified: Set(value.last_modified),
            host: Set(value.host),
            data: Set(value.data),
        }
    }
}

impl TryFrom<interaction::Model> for Interaction {
    type Error = DataLayerError;

    fn try_from(value: interaction::Model) -> Result<Self, Self::Error> {
        let id = Uuid::from_str(&value.id).map_err(|_| DataLayerError::MappingError)?;
        Ok(Self {
            id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            host: value.host,
            data: value.data,
        })
    }
}
