use one_core::model::interaction::{Interaction, UpdateInteractionRequest};
use one_core::model::organisation::Organisation;
use one_core::repository::error::DataLayerError;
use sea_orm::Set;

use crate::entity::interaction;

impl TryFrom<Interaction> for interaction::ActiveModel {
    type Error = DataLayerError;

    fn try_from(value: Interaction) -> Result<Self, DataLayerError> {
        let organisation_id = value.organisation.ok_or(DataLayerError::MappingError)?.id;
        Ok(Self {
            id: Set(value.id),
            created_date: Set(value.created_date),
            last_modified: Set(value.last_modified),
            data: Set(value.data),
            organisation_id: Set(organisation_id),
            nonce_id: Set(value.nonce_id),
            interaction_type: Set(value.interaction_type.into()),
            expires_at: Set(value.expires_at),
        })
    }
}

impl From<UpdateInteractionRequest> for interaction::ActiveModel {
    fn from(value: UpdateInteractionRequest) -> Self {
        Self {
            data: value.data.map(Set).unwrap_or_default(),
            ..Default::default()
        }
    }
}

pub(super) fn interaction_from_models(
    interaction: interaction::Model,
    organisation: Option<Organisation>,
) -> Interaction {
    Interaction {
        id: interaction.id,
        created_date: interaction.created_date,
        last_modified: interaction.last_modified,
        data: interaction.data,
        organisation,
        nonce_id: interaction.nonce_id,
        interaction_type: interaction.interaction_type.into(),
        expires_at: interaction.expires_at,
    }
}
