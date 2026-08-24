use std::sync::Arc;

use one_core::model::interaction::{Interaction, InteractionEcosystems, UpdateInteractionRequest};
use one_core::model::relation::Related;
use one_core::repository::error::DataLayerError;
use one_core::repository::organisation_repository::OrganisationRepository;
use sea_orm::Set;

use crate::entity::interaction;

impl TryFrom<Interaction> for interaction::ActiveModel {
    type Error = DataLayerError;

    fn try_from(value: Interaction) -> Result<Self, Self::Error> {
        Ok(Self {
            id: Set(value.id),
            created_date: Set(value.created_date),
            last_modified: Set(value.last_modified),
            data: Set(value.data),
            organisation_id: Set(value.organisation.id()),
            nonce_id: Set(value.nonce_id),
            interaction_type: Set(value.interaction_type.into()),
            expires_at: Set(value.expires_at),
            ecosystem: Set(value.ecosystem),
            ecosystem_data: Set(value
                .ecosystem_data
                .into_stored()
                .map_err(|_| DataLayerError::MappingError)?),
        })
    }
}

impl TryFrom<UpdateInteractionRequest> for interaction::ActiveModel {
    type Error = DataLayerError;

    fn try_from(value: UpdateInteractionRequest) -> Result<Self, Self::Error> {
        Ok(Self {
            data: value.data.map(Set).unwrap_or_default(),
            ecosystem: value.ecosystem.map(Set).unwrap_or_default(),
            ecosystem_data: value
                .ecosystem_data
                .map(|data| data.into_stored())
                .transpose()
                .map_err(|_| DataLayerError::MappingError)?
                .map(Set)
                .unwrap_or_default(),
            ..Default::default()
        })
    }
}

pub(crate) fn interaction_from_model(
    interaction: interaction::Model,
    organisation_repository: &Arc<dyn OrganisationRepository>,
) -> Interaction {
    Interaction {
        id: interaction.id,
        created_date: interaction.created_date,
        last_modified: interaction.last_modified,
        data: interaction.data,
        organisation: Related::new(interaction.organisation_id, organisation_repository.clone()),
        nonce_id: interaction.nonce_id,
        interaction_type: interaction.interaction_type.into(),
        expires_at: interaction.expires_at,
        ecosystem: interaction.ecosystem,
        ecosystem_data: InteractionEcosystems::from_stored(interaction.ecosystem_data),
    }
}
