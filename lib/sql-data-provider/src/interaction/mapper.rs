use std::str::FromStr;

use one_core::{model::interaction::Interaction, repository::error::DataLayerError};
use sea_orm::Set;
use url::Url;
use uuid::Uuid;

use crate::entity::interaction;

impl From<Interaction> for interaction::ActiveModel {
    fn from(value: Interaction) -> Self {
        Self {
            id: Set(value.id.to_string()),
            created_date: Set(value.created_date),
            last_modified: Set(value.last_modified),
            host: Set(value.host.as_ref().map(ToString::to_string)),
            data: Set(value.data),
        }
    }
}

impl TryFrom<interaction::Model> for Interaction {
    type Error = DataLayerError;

    fn try_from(value: interaction::Model) -> Result<Self, Self::Error> {
        let id = Uuid::from_str(&value.id)?;
        let host = value
            .host
            .map(|host| Url::parse(&host).map_err(|_| DataLayerError::MappingError))
            .transpose()?;

        Ok(Self {
            id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            host,
            data: value.data,
        })
    }
}
