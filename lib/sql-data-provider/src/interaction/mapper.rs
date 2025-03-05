use std::str::FromStr;

use one_core::model::interaction::{Interaction, UpdateInteractionRequest};
use one_core::model::organisation::Organisation;
use one_core::repository::error::DataLayerError;
use sea_orm::Set;
use time::OffsetDateTime;
use url::Url;
use uuid::Uuid;

use crate::entity::interaction;

impl TryFrom<Interaction> for interaction::ActiveModel {
    type Error = DataLayerError;

    fn try_from(value: Interaction) -> Result<Self, DataLayerError> {
        let organisation_id = value.organisation.ok_or(DataLayerError::MappingError)?.id;
        Ok(Self {
            id: Set(value.id.to_string()),
            created_date: Set(value.created_date),
            last_modified: Set(value.last_modified),
            host: Set(value.host.as_ref().map(ToString::to_string)),
            data: Set(value.data),
            organisation_id: Set(organisation_id),
        })
    }
}

impl TryFrom<UpdateInteractionRequest> for interaction::ActiveModel {
    type Error = DataLayerError;

    fn try_from(value: UpdateInteractionRequest) -> Result<Self, DataLayerError> {
        let organisation_id = value.organisation.ok_or(DataLayerError::MappingError)?.id;
        Ok(Self {
            id: Set(value.id.to_string()),
            last_modified: Set(OffsetDateTime::now_utc()),
            host: Set(value.host.as_ref().map(ToString::to_string)),
            data: Set(value.data),
            organisation_id: Set(organisation_id),
            ..Default::default()
        })
    }
}

pub(super) fn interaction_from_models(
    interaction: interaction::Model,
    organisation: Option<Organisation>,
) -> Result<Interaction, DataLayerError> {
    let id = Uuid::from_str(&interaction.id)?;
    let host = interaction
        .host
        .map(|host| Url::parse(&host).map_err(|_| DataLayerError::MappingError))
        .transpose()?;
    Ok(Interaction {
        id,
        created_date: interaction.created_date,
        last_modified: interaction.last_modified,
        host,
        data: interaction.data,
        organisation,
    })
}
