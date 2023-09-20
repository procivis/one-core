use std::str::FromStr;

use one_core::{
    model::interaction::{Interaction, InteractionId, InteractionRelations},
    repository::{error::DataLayerError, interaction_repository::InteractionRepository},
};
use sea_orm::{ActiveModelTrait, EntityTrait};
use uuid::Uuid;

use crate::{entity::interaction, error_mapper::to_data_layer_error};

use super::InteractionProvider;

#[async_trait::async_trait]
impl InteractionRepository for InteractionProvider {
    async fn create_interaction(
        &self,
        request: Interaction,
    ) -> Result<InteractionId, DataLayerError> {
        let interaction = interaction::ActiveModel::from(request)
            .insert(&self.db)
            .await
            .map_err(to_data_layer_error)?;

        Uuid::from_str(&interaction.id).map_err(|_| DataLayerError::MappingError)
    }

    async fn get_interaction(
        &self,
        id: &InteractionId,
        _relations: &InteractionRelations,
    ) -> Result<Interaction, DataLayerError> {
        let interaction = interaction::Entity::find_by_id(id.to_string())
            .one(&self.db)
            .await
            .map_err(|e| DataLayerError::GeneralRuntimeError(e.to_string()))?
            .ok_or(DataLayerError::RecordNotFound)?;

        interaction.try_into()
    }
}
