use std::str::FromStr;

use autometrics::autometrics;
use one_core::model::common::LockType;
use one_core::model::interaction::{
    Interaction, InteractionId, InteractionRelations, UpdateInteractionRequest,
};
use one_core::repository::error::DataLayerError;
use one_core::repository::interaction_repository::InteractionRepository;
use sea_orm::ActiveValue::Unchanged;
use sea_orm::prelude::Expr;
use sea_orm::sea_query::Query;
use sea_orm::{ActiveModelTrait, ConnectionTrait, EntityTrait, QuerySelect};
use shared_types::NonceId;
use uuid::Uuid;

use super::InteractionProvider;
use crate::entity::interaction;
use crate::interaction::mapper::interaction_from_models;
use crate::mapper::{map_lock_type, to_data_layer_error, to_update_data_layer_error};

#[autometrics]
#[async_trait::async_trait]
impl InteractionRepository for InteractionProvider {
    async fn create_interaction(
        &self,
        request: Interaction,
    ) -> Result<InteractionId, DataLayerError> {
        let interaction = interaction::ActiveModel::try_from(request)?
            .insert(&self.db)
            .await
            .map_err(to_data_layer_error)?;
        Ok(Uuid::from_str(&interaction.id)?)
    }

    async fn update_interaction(
        &self,
        id: InteractionId,
        request: UpdateInteractionRequest,
    ) -> Result<(), DataLayerError> {
        let mut model: interaction::ActiveModel = request.into();
        model.id = Unchanged(id.to_string());
        model
            .update(&self.db)
            .await
            .map_err(to_update_data_layer_error)?;
        Ok(())
    }

    async fn get_interaction(
        &self,
        id: &InteractionId,
        relations: &InteractionRelations,
        lock: Option<LockType>,
    ) -> Result<Option<Interaction>, DataLayerError> {
        let select = interaction::Entity::find_by_id(id.to_string());
        let select = match lock {
            None => select,
            Some(lock) => select.lock(map_lock_type(lock)),
        };
        let interaction = select
            .one(&self.db)
            .await
            .map_err(|e| DataLayerError::Db(e.into()))?;

        let Some(interaction) = interaction else {
            return Ok(None);
        };

        let organisation_id = interaction.organisation_id.to_owned();

        let organisation = if let Some(interaction_relations) = &relations.organisation {
            Some(
                self.organisation_repository
                    .get_organisation(&organisation_id, interaction_relations)
                    .await?
                    .ok_or(DataLayerError::MissingRequiredRelation {
                        relation: "interaction-organisation",
                        id: organisation_id.to_string(),
                    })?,
            )
        } else {
            None
        };

        let interaction = interaction_from_models(interaction, organisation)?;

        Ok(Some(interaction))
    }

    async fn mark_nonce_as_used(
        &self,
        interaction_id: &InteractionId,
        nonce_id: NonceId,
    ) -> Result<(), DataLayerError> {
        let stmt = self.db.get_database_backend().build(
            Query::update()
                .table(interaction::Entity)
                .value(interaction::Column::NonceId, nonce_id)
                .and_where(Expr::col(interaction::Column::Id).eq(interaction_id.to_string()))
                .and_where(Expr::col(interaction::Column::NonceId).is_null()),
        );
        let result = self.db.execute(stmt).await.map_err(to_data_layer_error)?;
        if result.rows_affected() == 0 {
            return Err(DataLayerError::RecordNotUpdated);
        }
        Ok(())
    }

    async fn delete_interaction(&self, id: &InteractionId) -> Result<(), DataLayerError> {
        interaction::Entity::delete_by_id(*id)
            .exec(&self.db)
            .await
            .map_err(|e| DataLayerError::Db(e.into()))?;
        Ok(())
    }
}
