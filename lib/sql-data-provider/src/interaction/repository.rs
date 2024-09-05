use std::str::FromStr;

use autometrics::autometrics;
use one_core::model::interaction::{Interaction, InteractionId, InteractionRelations};
use one_core::repository::error::DataLayerError;
use one_core::repository::interaction_repository::InteractionRepository;
use sea_orm::{ActiveModelTrait, DbErr, EntityTrait};
use uuid::Uuid;

use super::InteractionProvider;
use crate::entity::interaction;
use crate::mapper::to_data_layer_error;

#[autometrics]
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

        Ok(Uuid::from_str(&interaction.id)?)
    }

    async fn update_interaction(&self, request: Interaction) -> Result<(), DataLayerError> {
        let model: interaction::ActiveModel = request.into();

        model.update(&self.db).await.map_err(|e| match e {
            DbErr::RecordNotUpdated => DataLayerError::RecordNotUpdated,
            _ => DataLayerError::Db(e.into()),
        })?;
        Ok(())
    }

    async fn get_interaction(
        &self,
        id: &InteractionId,
        _relations: &InteractionRelations,
    ) -> Result<Option<Interaction>, DataLayerError> {
        let interaction = interaction::Entity::find_by_id(id.to_string())
            .one(&self.db)
            .await
            .map_err(|e| DataLayerError::Db(e.into()))?;

        let Some(interaction) = interaction else {
            return Ok(None);
        };

        let interaction = interaction.try_into()?;

        Ok(Some(interaction))
    }

    async fn delete_interaction(&self, id: &InteractionId) -> Result<(), DataLayerError> {
        let _ = interaction::Entity::delete_by_id(id.to_string())
            .exec(&self.db)
            .await
            .map_err(|e| DataLayerError::Db(e.into()))?;
        Ok(())
    }
}
