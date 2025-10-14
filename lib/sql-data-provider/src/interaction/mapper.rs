use std::str::FromStr;

use one_core::model::interaction::{Interaction, UpdateInteractionRequest};
use one_core::model::organisation::Organisation;
use one_core::repository::error::DataLayerError;
use sea_orm::Set;
use shared_types::NonceId;
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
            nonce_id: Set(value.nonce_id.map(NonceId::from)),
            interaction_type: Set(value.interaction_type.into()),
        })
    }
}

impl From<UpdateInteractionRequest> for interaction::ActiveModel {
    fn from(value: UpdateInteractionRequest) -> Self {
        Self {
            host: value
                .host
                .map(|url| Set(url.map(|url| url.to_string())))
                .unwrap_or_default(),
            data: value.data.map(Set).unwrap_or_default(),
            nonce_id: value
                .nonce_id
                .map(|id| Set(id.map(NonceId::from)))
                .unwrap_or_default(),
            ..Default::default()
        }
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
        nonce_id: interaction.nonce_id.map(Uuid::from),
        interaction_type: interaction.interaction_type.into(),
    })
}
