use one_core::{
    model::interaction::{Interaction, InteractionId, InteractionRelations},
    repository::{error::DataLayerError, interaction_repository::InteractionRepository},
};
use sea_orm::{ActiveModelTrait, DbErr, EntityTrait};
use std::str::FromStr;
use uuid::Uuid;

use super::InteractionProvider;
use crate::{entity::interaction, mapper::to_data_layer_error};

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

    async fn update_interaction(&self, request: Interaction) -> Result<(), DataLayerError> {
        let model: interaction::ActiveModel = request.into();

        model.update(&self.db).await.map_err(|e| match e {
            DbErr::RecordNotUpdated => DataLayerError::RecordNotUpdated,
            _ => DataLayerError::GeneralRuntimeError(e.to_string()),
        })?;
        Ok(())
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
